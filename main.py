from __future__ import annotations

import csv
import html
import io
import ipaddress
import json
import os
import re
import sqlite3

from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from threat_intel import enrich_indicators
from ml_detector import get_ml_status, predict_ml


# =========================================================
# CONFIGURATION
# =========================================================

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

DB_PATH = Path(
    os.getenv("MAILSLEUTH_DB", str(ROOT / "mailsleuth.db"))
)

MAX_UPLOAD = 5 * 1024 * 1024
MAX_BODY_CHARS = 200_000
MAX_HEADERS_CHARS = 100_000

API_KEY = os.getenv("MAILSLEUTH_API_KEY", "").strip()

app = FastAPI(
    title="MailSleuth",
    version="2.0.0",
    description=(
        "Phishing-risk analysis, email header forensics, "
        "optional threat intelligence, and ML evaluation."
    ),
)

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC)),
    name="static",
)


# =========================================================
# REQUEST MODEL
# =========================================================

class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=MAX_BODY_CHARS)
    raw_headers: str = Field(
        default="",
        max_length=MAX_HEADERS_CHARS,
    )

    include_threat_intel: bool = False
    include_ml: bool = True


# =========================================================
# DATABASE
# =========================================================

def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                risk_score INTEGER NOT NULL,
                rule_score INTEGER NOT NULL DEFAULT 0,
                classification TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                urls_json TEXT NOT NULL,
                auth_json TEXT NOT NULL,
                headers_json TEXT NOT NULL,
                relay_json TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                threat_json TEXT NOT NULL,
                ml_json TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT ''
            )
        """)

        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_created
            ON analyses(created_at)
        """)


init_db()


# =========================================================
# SECURITY MIDDLEWARE
# =========================================================

@app.middleware("http")
async def security_headers_and_api_key(
    request: Request,
    call_next,
):
    if (
        API_KEY
        and request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.url.path.startswith("/api/")
    ):
        supplied = request.headers.get("x-api-key", "")

        if supplied != API_KEY:
            return JSONResponse(
                {"detail": "Invalid or missing API key."},
                status_code=401,
            )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

        
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )


    return response


# =========================================================
# VALIDATION AND GENERAL HELPERS
# =========================================================

def classify(score: int) -> str:
    if score >= 70:
        return "High Risk"
    if score >= 40:
        return "Suspicious"
    return "Low Risk"


def validate_email_input(payload: AnalyzeRequest):
    values = (
        payload.sender,
        payload.subject,
        payload.body,
        payload.raw_headers,
    )

    if not any(value.strip() for value in values):
        raise HTTPException(
            status_code=400,
            detail=(
                "Please provide an email sender, subject, "
                "body, or headers."
            ),
        )


def extract_urls(text: str) -> list[str]:
    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    matches = re.findall(pattern, text or "")

    results = []

    for value in matches:
        value = value.rstrip(".,;:!?)\"]}")

        if value and value not in results:
            results.append(value[:2048])

    return results[:100]


# =========================================================
# HEADER FORENSICS
# =========================================================

def parse_headers(raw: str) -> dict:
    result = {
        "from": "",
        "reply_to": "",
        "return_path": "",
        "message_id": "",
        "received_headers": [],
        "authentication_results": [],
    }

    if not raw:
        return result

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            raw.encode("utf-8", errors="replace")
            + b"\r\n\r\n"
        )

        result["from"] = str(message.get("From", ""))[:500]
        result["reply_to"] = str(
            message.get("Reply-To", "")
        )[:500]
        result["return_path"] = str(
            message.get("Return-Path", "")
        )[:500]
        result["message_id"] = str(
            message.get("Message-ID", "")
        )[:500]

        result["received_headers"] = [
            str(value)[:4000]
            for value in message.get_all("Received", [])[:100]
        ]

        result["authentication_results"] = [
            str(value)[:4000]
            for header_name in (
                "Authentication-Results",
                "Received-SPF",
            )
            for value in message.get_all(
                header_name, []
            )[:20]
        ]

    except Exception:
        pass

    return result


def parse_auth(headers: dict) -> dict[str, str]:
    text = "\n".join(
        headers.get("authentication_results", [])
    )

    results = {}

    for name in ("spf", "dkim", "dmarc"):
        pattern = (
            r"(?i)(?<![\w-])"
            + name
            + r"\s*=\s*"
            + r"(pass|fail|softfail|neutral|none|"
              r"temperror|permerror)"
        )

        matches = re.findall(pattern, text)

        results[name.upper()] = (
            matches[0].lower()
            if matches
            else "not reported"
        )

    return results


def relay_path(received: list[str]) -> dict:
    hops = []

    for number, header in enumerate(received, start=1):
        candidates = re.findall(
            r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
            header,
        )

        ips = []

        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)

                if candidate not in ips:
                    ips.append(candidate)

            except ValueError:
                continue

        details = []

        for ip in ips:
            address = ipaddress.ip_address(ip)

            details.append({
                "ip": ip,
                "scope": (
                    "public"
                    if address.is_global
                    else "private/reserved"
                ),
            })

        hops.append({
            "hop": number,
            "header": header,
            "ips": ips,
            "ip_details": details,
        })

    return {
        "hop_count": len(hops),
        "hops": hops,
        "note": (
            "Received headers can be forged; extracted hops "
            "do not prove a trusted route."
        ),
    }


# =========================================================
# RULE-BASED PHISHING DETECTION
# =========================================================

def rule_analysis(
    sender: str,
    subject: str,
    body: str,
    raw_headers: str,
) -> dict:
    headers = parse_headers(raw_headers)
    auth = parse_auth(headers)

    content = f"{sender}\n{subject}\n{body}"
    urls = extract_urls(content)

    findings = []

    def add(rule, points, explanation, evidence=""):
        findings.append({
            "rule": rule,
            "points": points,
            "explanation": explanation,
            "evidence": evidence[:500],
        })

    if re.search(
        r"(?i)\b(urgent|immediately|within 24 hours|act now|"
        r"account suspended|final warning|verify now|"
        r"payment overdue)\b",
        content,
    ):
        add(
            "urgency_language",
            12,
            "Pressure language may be used to rush a recipient.",
            "Urgency-related wording matched",
        )

    if re.search(
        r"(?i)\b(password|login credentials|verify your account|"
        r"confirm your identity|one[- ]time password|\botp\b)\b",
        content,
    ):
        add(
            "credential_request",
            18,
            "The message mentions credentials or account verification.",
            "Credential-related wording matched",
        )

    address = parseaddr(sender)[1] or sender

    domain = (
        address.rsplit("@", 1)[-1].strip(" >").lower()
        if "@" in address
        else ""
    )

    lookalikes = (
        "paypa1",
        "micros0ft",
        "g00gle",
        "amaz0n",
        "app1e",
    )

    if domain and (
        domain.startswith("xn--")
        or any(item in domain for item in lookalikes)
    ):
        add(
            "lookalike_sender_domain",
            22,
            "Sender domain resembles a known lookalike pattern.",
            domain,
        )

    ip_url = False

    for url in urls:
        parsed = urlparse(
            url
            if url.lower().startswith(("http://", "https://"))
            else "http://" + url
        )

        try:
            ipaddress.ip_address(parsed.hostname or "")
            ip_url = True
        except ValueError:
            pass

    if ip_url:
        add(
            "ip_literal_url",
            18,
            "At least one link uses an IP address instead of a domain.",
            "IP-based URL detected",
        )

    if len(urls) >= 4:
        add(
            "many_links",
            8,
            "The message contains four or more links.",
            f"{len(urls)} URLs detected",
        )

    from_address = parseaddr(
        headers["from"]
    )[1]

    reply_address = parseaddr(
        headers["reply_to"]
    )[1]

    from_domain = (
        from_address.rsplit("@", 1)[-1].lower()
        if "@" in from_address
        else ""
    )

    reply_domain = (
        reply_address.rsplit("@", 1)[-1].lower()
        if "@" in reply_address
        else ""
    )

    if (
        from_domain
        and reply_domain
        and from_domain != reply_domain
    ):
        add(
            "reply_to_mismatch",
            12,
            "From and Reply-To domains differ; investigate the discrepancy.",
            f"{from_domain} != {reply_domain}",
        )

    for name, status in auth.items():
        if status in ("fail", "softfail", "permerror"):
            add(
                f"auth_{name.lower()}_{status}",
                12,
                (
                    f"Supplied headers report {name}={status}; "
                    "this is not independently verified."
                ),
                f"{name}={status}",
            )

    rule_score = min(
        100,
        sum(item["points"] for item in findings),
    )

    if not findings:
        findings.append({
            "rule": "no_rule_triggered",
            "points": 0,
            "explanation": (
                "No configured heuristic matched. "
                "This is not proof the email is safe."
            ),
            "evidence": "",
        })

    recommendations = []

    if rule_score >= 40:
        recommendations.append(
            "Do not click links or open attachments until "
            "the sender and request are independently verified."
        )

    if any(
        status in ("fail", "softfail", "permerror")
        for status in auth.values()
    ):
        recommendations.append(
            "Have the mail administrator verify authentication "
            "results against trusted mail logs and DNS."
        )

    if urls:
        recommendations.append(
            "Inspect link destinations carefully and navigate "
            "to known official sites directly."
        )

    if not recommendations:
        recommendations.append(
            "Treat the score as a triage aid, not a guarantee. "
            "Verify unexpected requests through a separate channel."
        )

    return {
        "headers": headers,
        "auth_results": auth,
        "relay_analysis": relay_path(
            headers["received_headers"]
        ),
        "urls_found": urls,
        "findings": findings,
        "rule_score": rule_score,
        "recommendations": recommendations,
        "sender_domain": domain,
    }


# =========================================================
# COMBINED ANALYSIS
# =========================================================

def analyze_payload(payload: AnalyzeRequest) -> dict:
    validate_email_input(payload)

    base = rule_analysis(
        payload.sender,
        payload.subject,
        payload.body,
        payload.raw_headers,
    )

    if payload.include_threat_intel:
        intel = enrich_indicators(
            base["sender_domain"],
            base["urls_found"],
        )
    else:
        intel = {
            "enabled": False,
            "domain": None,
            "url_reputation": [],
            "errors": [],
        }

    if payload.include_ml:
        ml = predict_ml(
            payload.sender,
            payload.subject,
            payload.body,
        )
    else:
        ml = {
            "available": False,
            "reason": "ML disabled for this request",
        }

    combined_score = base["rule_score"]

    if ml.get("available"):
        probability = float(
            ml.get("phishing_probability", 0)
        )

        if probability >= 0.85:
            combined_score = max(combined_score, 70)
        elif probability >= 0.65:
            combined_score = max(combined_score, 40)

        if probability >= 0.65:
            base["recommendations"].append(
                "The ML model flagged this message. "
                "Review its prediction and the evidence manually."
            )

    combined_score = min(100, combined_score)

    result = {
        "sender": (
            payload.sender or base["headers"]["from"]
        ),
        "subject": payload.subject,
        "risk_score": combined_score,
        "classification": classify(combined_score),
        "rule_score": base["rule_score"],
        "findings": base["findings"],
        "urls_found": base["urls_found"],
        "auth_results": base["auth_results"],
        "header_forensics": base["headers"],
        "relay_analysis": base["relay_analysis"],
        "recommendations": base["recommendations"],
        "threat_intelligence": intel,
        "ml_analysis": ml,
        "model_note": (
            "Heuristic evidence is shown separately from ML. "
            "Authentication results are parsed from supplied "
            "headers, not independently verified."
        ),
    }

    if intel.get("alerts"):
        result["recommendations"].insert(
            0,
            "Threat-intelligence lookup returned an alert. "
            "Verify the finding with the provider.",
        )

    return result


# =========================================================
# SAVE AND READ ANALYSES
# =========================================================

def save_result(result: dict, body: str) -> dict:
    created = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    with connect_db() as con:
        cursor = con.execute(
            """
            INSERT INTO analyses (
                created_at, sender, subject, risk_score,
                rule_score, classification, findings_json,
                urls_json, auth_json, headers_json, relay_json,
                recommendations_json, threat_json, ml_json, body
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created,
                result["sender"],
                result["subject"],
                result["risk_score"],
                result["rule_score"],
                result["classification"],
                json.dumps(result["findings"]),
                json.dumps(result["urls_found"]),
                json.dumps(result["auth_results"]),
                json.dumps(result["header_forensics"]),
                json.dumps(result["relay_analysis"]),
                json.dumps(result["recommendations"]),
                json.dumps(result["threat_intelligence"]),
                json.dumps(result["ml_analysis"]),
                body[:MAX_BODY_CHARS],
            ),
        )

        result["id"] = cursor.lastrowid
        result["created_at"] = created

    return result


def row_result(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "sender": row["sender"],
        "subject": row["subject"],
        "risk_score": row["risk_score"],
        "rule_score": row["rule_score"],
        "classification": row["classification"],
        "findings": json.loads(row["findings_json"]),
        "urls_found": json.loads(row["urls_json"]),
        "auth_results": json.loads(row["auth_json"]),
        "header_forensics": json.loads(row["headers_json"]),
        "relay_analysis": json.loads(row["relay_json"]),
        "recommendations": json.loads(
            row["recommendations_json"]
        ),
        "threat_intelligence": json.loads(
            row["threat_json"]
        ),
        "ml_analysis": json.loads(row["ml_json"]),
    }


# =========================================================
# DASHBOARD AND HEALTH
# =========================================================

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "MailSleuth",
        "version": "2.0.0",
    }


# =========================================================
# ANALYZE EMAIL TEXT
# =========================================================

@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    # Reject empty input before analysis or database writes.
    validate_email_input(payload)

    result = analyze_payload(payload)

    return save_result(result, payload.body)


# =========================================================
# ANALYZE UPLOADED EML
# =========================================================

@app.post("/api/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    include_threat_intel: bool = False,
    include_ml: bool = True,
):
    if (
        not file.filename
        or Path(file.filename).suffix.lower() != ".eml"
    ):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    raw = await file.read(MAX_UPLOAD + 1)

    if len(raw) > MAX_UPLOAD:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 5 MB limit.",
        )

    if not raw.strip():
        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty.",
        )

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw)

        sender = str(message.get("From", ""))[:500]
        subject = str(message.get("Subject", ""))[:1000]

        bodies = []

        parts = (
            message.walk()
            if message.is_multipart()
            else [message]
        )

        for part in parts:
            if (
                part.get_content_type() == "text/plain"
                and not part.get_filename()
            ):
                try:
                    bodies.append(str(part.get_content()))
                except Exception:
                    continue

        body = "\n".join(bodies)[:MAX_BODY_CHARS]

        raw_headers = (
            raw.split(b"\r\n\r\n", 1)[0]
            .split(b"\n\n", 1)[0]
            .decode("utf-8", errors="replace")[
                :MAX_HEADERS_CHARS
            ]
        )

        payload = AnalyzeRequest(
            sender=sender,
            subject=subject,
            body=body,
            raw_headers=raw_headers,
            include_threat_intel=include_threat_intel,
            include_ml=include_ml,
        )

        validate_email_input(payload)

        result = analyze_payload(payload)
        result = save_result(result, body)

        result["uploaded_filename"] = Path(
            file.filename
        ).name

        return result

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to parse this email file "
                f"({type(exc).__name__})."
            ),
        )


# =========================================================
# DASHBOARD SUMMARY
# =========================================================

@app.get("/api/dashboard-summary")
def dashboard_summary():
    with connect_db() as con:
        rows = con.execute(
            "SELECT risk_score FROM analyses"
        ).fetchall()

    scores = [row["risk_score"] for row in rows]
    count = len(scores)

    return {
        "total_analyses": count,
        "high_risk": sum(score >= 70 for score in scores),
        "suspicious": sum(
            40 <= score < 70 for score in scores
        ),
        "low_risk": sum(score < 40 for score in scores),
        "average_risk": (
            round(sum(scores) / count, 1)
            if count
            else 0
        ),
    }


# =========================================================
# HISTORY
# =========================================================

@app.get("/api/history")
def history(
    q: str = "",
    classification: str = "",
    limit: int = 100,
):
    limit = max(1, min(limit, 500))

    sql = "SELECT * FROM analyses"
    clauses = []
    params = []

    if q:
        clauses.append(
            "(sender LIKE ? OR subject LIKE ?)"
        )
        search = f"%{q[:200]}%"
        params.extend([search, search])

    if classification in (
        "Low Risk",
        "Suspicious",
        "High Risk",
    ):
        clauses.append("classification = ?")
        params.append(classification)

    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with connect_db() as con:
        rows = con.execute(sql, params).fetchall()

    return [row_result(row) for row in rows]


# =========================================================
# FORENSIC REPORT
# =========================================================

@app.get("/api/report/{analysis_id}")
def report(analysis_id: int):
    with connect_db() as con:
        row = con.execute(
            "SELECT * FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    data = row_result(row)
    esc = lambda value: html.escape(str(value or ""))

    findings_html = "".join(
        (
            f"<li><b>{esc(item['rule'])}</b> "
            f"(+{item['points']}): "
            f"{esc(item['explanation'])}<br>"
            f"<small>Evidence: "
            f"{esc(item.get('evidence', ''))}</small></li>"
        )
        for item in data["findings"]
    )

    auth_html = "".join(
        f"<li>{esc(key)}: {esc(value)}</li>"
        for key, value in data["auth_results"].items()
    )

    hops_html = "".join(
        (
            f"<li>Hop {hop['hop']}: "
            f"{esc(hop['header'])}<br>IPs: "
            f"{esc(', '.join(hop['ips']) or 'none')}</li>"
        )
        for hop in data["relay_analysis"]["hops"]
    ) or "<li>No Received headers found.</li>"

    recommendations_html = "".join(
        f"<li>{esc(item)}</li>"
        for item in data["recommendations"]
    )

    urls_html = "".join(
        f"<li>{esc(url)}</li>"
        for url in data["urls_found"]
    ) or "<li>None found.</li>"

    intel_html = esc(
        json.dumps(data["threat_intelligence"], indent=2)
    )

    ml_html = esc(
        json.dumps(data["ml_analysis"], indent=2)
    )

    page = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>MailSleuth report #{data['id']}</title>
<style>
body {{
    font: 16px Arial, sans-serif;
    max-width: 900px;
    margin: 35px auto;
    padding: 0 20px;
    color: #172033;
}}
section {{
    border: 1px solid #ccd4e0;
    border-radius: 10px;
    padding: 16px;
    margin: 14px 0;
}}
h1 {{ color: #164b80; }}
small {{ color: #596579; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
</style>
</head>
<body>
<h1>MailSleuth Forensic Report</h1>
<p>Analysis #{data['id']} · {esc(data['created_at'])}</p>

<section>
<h2>Risk: {data['risk_score']}/100 —
{esc(data['classification'])}</h2>
<p>
Sender: {esc(data['sender'])}<br>
Subject: {esc(data['subject'])}<br>
Rule score: {data['rule_score']}<br>
Combined triage score: {data['risk_score']}
</p>
</section>

<section>
<h2>Detected indicators</h2>
<ul>{findings_html}</ul>
</section>

<section>
<h2>Authentication results (header-reported)</h2>
<ul>{auth_html}</ul>
<p>These results are not independently verified.</p>
</section>

<section>
<h2>Relay path ({data['relay_analysis']['hop_count']} hops)</h2>
<ol>{hops_html}</ol>
<p><small>{esc(data['relay_analysis']['note'])}</small></p>
</section>

<section>
<h2>URLs found</h2>
<ul>{urls_html}</ul>
</section>

<section>
<h2>Recommendations</h2>
<ul>{recommendations_html}</ul>
</section>

<section>
<h2>Threat intelligence</h2>
<pre>{intel_html}</pre>
</section>

<section>
<h2>ML signal</h2>
<pre>{ml_html}</pre>
</section>

<p><small>
Rule-based prototype. Header claims are not independently
verified. Low risk does not mean safe.
</small></p>
</body>
</html>"""

    return HTMLResponse(
        page,
        headers={
            "Content-Disposition": (
                f'attachment; filename="mailsleuth-report-'
                f'{analysis_id}.html"'
            )
        },
    )


# =========================================================
# CSV EXPORT
# =========================================================

@app.get("/api/export.csv")
def export_csv():
    with connect_db() as con:
        rows = con.execute(
            "SELECT * FROM analyses ORDER BY id DESC"
        ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow([
        "id",
        "created_at",
        "sender",
        "subject",
        "risk_score",
        "classification",
        "findings",
        "urls",
        "auth_results",
        "relay_analysis",
    ])

    def safe_cell(value):
        text = str(value if value is not None else "")

        if text.startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + text

        return text

    for row in rows:
        writer.writerow([
            row["id"],
            row["created_at"],
            safe_cell(row["sender"]),
            safe_cell(row["subject"]),
            row["risk_score"],
            row["classification"],
            row["findings_json"],
            row["urls_json"],
            row["auth_json"],
            row["relay_json"],
        ])

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="mailsleuth-history.csv"'
        },
    )


# =========================================================
# ML STATUS AND EVALUATION
# =========================================================

@app.get("/api/ml/status")
def ml_status():
    return get_ml_status()


@app.post("/api/ml/evaluate")
def ml_evaluate():
    from ml_detector import train_and_evaluate

    try:
        return train_and_evaluate()

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "ML evaluation failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        )