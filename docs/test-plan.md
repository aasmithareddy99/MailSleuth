# MailSleuth Test Plan

| ID | Feature | Test input / action | Expected result |
|---|---|---|---|
| T01 | Health | GET `/health` | JSON status `ok` |
| T02 | Text analysis | Submit a synthetic suspicious message | 0–100 score, classification and explanations |
| T03 | Relay path | Supply two `Received` headers | `hop_count=2`; each hop has header and extracted IPs |
| T04 | Authentication | Supply SPF/DKIM/DMARC result headers | Parsed status displayed as header-reported |
| T05 | Malformed headers | Send unusual or incomplete header text | Request remains handled; no traceback exposed |
| T06 | Upload extension | Upload `.txt` | HTTP 400 |
| T07 | Upload size | Upload >5 MB `.eml` | HTTP 413 |
| T08 | History | Analyze two messages, query history | Both saved and searchable |
| T09 | Summary | Analyze examples of different scores | Counts and average update |
| T10 | CSV export | Download CSV | Header row and saved analyses present; formula-like fields escaped |
| T11 | Forensic report | Open `/api/report/{id}` | Report includes score, findings, auth, hops, URLs and recommendations |
| T12 | ML evaluation | POST `/api/ml/evaluate` | Holdout metrics and confusion matrix returned; caveat included |
| T13 | ML prediction | Analyze after training | Model signal returned separately from rule score |
| T14 | Threat intel off | Leave checkbox off | No DNS/reputation lookup requested |
| T15 | Threat intel on | Enable checkbox | DNS status returned; URLhaus gracefully reports not configured/error if unavailable |
| T16 | API key | Configure key and omit header on write API | HTTP 401 |
| T17 | HTML safety | Include `<script>` in sender/body | Displayed as text / escaped in report, never executed |

Automated smoke tests run with `python -m pytest -q`. Manual UI tests are still required in a browser and should be documented with date, build, test input, observed result, and screenshot before claiming full verification.
