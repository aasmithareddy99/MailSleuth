# MailSleuth — Complete SIH Prototype

MailSleuth is a local-first email phishing triage and header-forensics prototype. It combines an auditable rule engine, optional TF-IDF + Logistic Regression model, opt-in DNS / URLhaus enrichment, SQLite history, CSV export, downloadable HTML forensic reports, and a dashboard.

## 1. Requirements and setup (Windows PowerShell)

Python 3.10+ is recommended. From this folder:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

If activation is blocked, use `venv\Scripts\python.exe -m pip install -r requirements.txt` and `venv\Scripts\python.exe -m uvicorn main:app --reload`.

Open `http://127.0.0.1:8000/` for the dashboard and `http://127.0.0.1:8000/docs` for API docs.

## 2. Feature map

1. **Relay-path display:** Received header hops and IPs are returned as `relay_analysis` and displayed in the report panel.
2. **Testing:** `pytest -q` covers health, dashboard serving, analysis, header/auth parsing, relay parsing, history, statistics, report export, CSV export, upload validation, and body-size validation.
3. **Forensic report:** `GET /api/report/{id}` downloads an HTML report with score, classification, evidence, auth values, relay hops, URLs, recommendations, threat-intelligence output, and ML signal.
4. **Detection/explanations:** Each rule has a rule ID, points, explanation and limited evidence. Malformed input is constrained by Pydantic and parser error handling. The bundled test dataset is synthetic; evaluate false positives with representative legitimate and phishing examples.
5. **Threat intelligence:** Enable the checkbox to resolve the sender domain and optionally query URLhaus for the sender domain. The email body and full email are not sent. DNS lookup still reveals the domain to the configured DNS resolver. External checks are opt-in and may fail or time out.
6. **ML:** `POST /api/ml/evaluate` trains and evaluates TF-IDF + Logistic Regression using a stratified holdout split; the dashboard has a Train / evaluate ML button. Metrics include accuracy, precision, recall, F1, confusion matrix and classification report. The included examples are synthetic and only validate the pipeline, not real-world efficacy.
7. **Hardening:** 5 MB upload cap, extension validation, Pydantic size bounds, no email HTML rendering, escaped report output, safe CSV cells, security headers, no permissive CORS, bounded queries, optional API key for write endpoints.
8. **SIH materials:** `docs/architecture.md`, `docs/test-plan.md`, and `docs/sih-presentation.md`.

## 3. ML training

Click **Train / evaluate ML** in the dashboard or run:

```powershell
Invoke-RestMethod -Method POST http://127.0.0.1:8000/api/ml/evaluate
```

The model is saved at `data/phishing_model.joblib`. The API reports test-set metrics from the fixed split. Do not describe synthetic-data metrics as production accuracy. Replace the dataset with properly labeled, permissioned, representative samples, deduplicate it, and use a temporal or sender/domain-separated test split before claiming useful performance.

## 4. Optional URLhaus lookup

Only enable threat intelligence when you understand the privacy tradeoff. Sender and linked URL-host DNS checks run when the checkbox is enabled. URLhaus host reputation lookups require an API key in `URLHAUS_AUTH_KEY`:

```powershell
$env:URLHAUS_AUTH_KEY = "YOUR_AUTH_KEY"
python -m uvicorn main:app --reload
```

Only sender/linked URL hostnames are submitted to URLhaus by this adapter, never the email body or full URL path/query. Do not paste secrets into source control. Provider terms, key requirements, connectivity and API behavior can change; the integration handles failures without failing email analysis.

## 5. Optional API key

For local/demo usage no key is required. To protect write endpoints, set a long random key before starting the server:

```powershell
$env:MAILSLEUTH_API_KEY = "replace-with-a-long-random-secret"
python -m uvicorn main:app --reload
```

Then send `X-API-Key: replace-with-a-long-random-secret` to `/api/*` POST endpoints. This is a basic demo control, not a replacement for user authentication, HTTPS, rate limiting, audit policy, or a production identity provider.

## 6. API endpoints

- `GET /`, `GET /health`
- `POST /api/analyze` — JSON: `sender`, `subject`, `body`, `raw_headers`, `include_ml`, `include_threat_intel`
- `POST /api/analyze-file` — multipart `.eml`, max 5 MB
- `GET /api/history?q=&classification=&limit=`
- `GET /api/dashboard-summary`
- `GET /api/report/{analysis_id}` — downloadable HTML report
- `GET /api/export.csv`
- `GET /api/ml/status`
- `POST /api/ml/evaluate`
- `GET /docs`

## 7. Known limitations / truthful claims

- This is a triage prototype, not a mail gateway or a replacement for an enterprise email security product.
- SPF/DKIM/DMARC values are parsed from supplied headers. The application does not independently verify SPF DNS policy, DKIM signatures, or DMARC alignment.
- Received headers can be forged. Relay extraction is descriptive, not proof of a trusted route.
- Rule-based and ML scores can be wrong. The model is trained on a small synthetic dataset and must not be presented as validated on real traffic.
- DNS and reputation lookups may expose a domain to external infrastructure. They are opt-in and errors do not stop local analysis.
- For deployment: use HTTPS, a real authentication/authorization layer, rate limits, CSRF strategy where relevant, secrets management, database retention/deletion controls, structured audit logs, dependency scanning, and a security review.

## 8. Run tests

```powershell
python -m pytest -q
```

## 9. Manual acceptance checklist

- [ ] Start server and open dashboard.
- [ ] Analyze `data/sample-suspicious.eml`; verify score, findings and relay hops.
- [ ] Analyze `data/sample-legitimate.eml`; compare findings and score. Do not assume every legitimate message must score zero.
- [ ] Confirm From / Reply-To / Return-Path / Message-ID and header-reported authentication values are visible.
- [ ] Verify new analysis appears in history; test search and classification filter.
- [ ] Download report and open it; verify evidence, authentication, hops and recommendations.
- [ ] Export CSV and inspect rows.
- [ ] Click **Train / evaluate ML**; record the returned test-set metrics and caveat.
- [ ] Analyze a sample again and confirm ML signal is shown separately.
- [ ] Enable threat intelligence only if you accept the DNS/provider privacy implications.
- [ ] Run `python -m pytest -q` and save the terminal output for SIH evidence.
