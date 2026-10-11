# SIH Presentation Outline — MailSleuth

## Slide 1 — Title
**MailSleuth: Explainable Email Phishing Detection and Header Forensics**

## Slide 2 — Problem
Phishing and impersonation messages use urgency, credential harvesting, lookalike domains and deceptive reply paths. Users need a quick, evidence-based triage workflow rather than an unexplained binary verdict.

## Slide 3 — Proposed solution
MailSleuth combines explainable rules, header forensics, relay-hop extraction, optional ML classification, opt-in domain intelligence and downloadable evidence reports in one local-first dashboard.

## Slide 4 — Architecture
Show `docs/architecture.md`. Describe dashboard → FastAPI → parser/risk engine → optional ML/intelligence → SQLite → report/history.

## Slide 5 — Core features
- Text and `.eml` analysis (5 MB limit)
- Risk score and per-rule explanation
- From / Reply-To / Return-Path / Message-ID
- SPF/DKIM/DMARC header-result parsing
- Received header hop/IP extraction
- Searchable history, summary, CSV and HTML report

## Slide 6 — AI/ML component
TF-IDF text features + Logistic Regression; stratified holdout; report precision, recall, F1 and confusion matrix. State clearly that the bundled dataset is synthetic and that metrics are demonstration-only until evaluated on representative labeled email.

## Slide 7 — Threat intelligence and privacy
Optional sender-domain DNS lookup and URLhaus host lookup. The email body is not submitted. DNS queries reveal the domain to the resolver; external lookup is opt-in and failures are handled safely.

## Slide 8 — Security and responsible use
Input limits, `.eml` size cap, HTML escaping, safe CSV output, security headers, optional API key. Header claims are not independently verified and relay headers may be forged. Human review remains necessary.

## Slide 9 — Testing and demonstration
Show results from `pytest -q`, then analyze a synthetic suspicious message, inspect hop count, open report, filter history, export CSV, and train/evaluate the ML model.

## Slide 10 — Innovation, limitations and future scope
**Innovation:** unified triage, explainable rule evidence, relay-path visibility, privacy-conscious opt-in enrichment, and reportable investigations.
**Limitations:** synthetic ML dataset, heuristic false positives, no independent SPF/DKIM/DMARC verification, and no production identity system.
**Future:** curated and consented dataset, sender/domain-separated evaluation, stronger URL parsing, organization-specific policies, analyst feedback loop and secure deployment.

## Demo script (5 minutes)
1. Open dashboard and explain the local API.
2. Load the synthetic suspicious demo sample and analyze it.
3. Point out the score, evidence points and recommendations.
4. Show SPF/DKIM/DMARC as header-reported and inspect relay hops/IPs.
5. Download the forensic report and export history CSV.
6. Click Train / evaluate ML and explain the metrics and synthetic-data limitation.
7. Briefly show threat intelligence is opt-in and discuss privacy boundaries.
