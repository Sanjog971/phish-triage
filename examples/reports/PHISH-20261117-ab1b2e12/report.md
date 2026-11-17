# Phishing triage report - PHISH-20261117-ab1b2e12

| | |
|---|---|
| **Verdict** | **LOW RISK** - score 0/100, confidence low |
| **Sample** | 03\_benign\_vendor\_newsletter\[.\]eml · SHA-256 `ab1b2e12c5d818b2e1c791ce02a1537c9232cd6060b6d231d953e4e2c2d9b4e0` |
| **Analyzed** | 2026-11-17 10:21 UTC · phish-triage 1.0.0 |
| **Reputation** | offline \(local intel only; no external requests\) |

## Summary

No significant phishing traits found; external reputation not checked \(offline run\). Not a clearance - weigh the reporter's context.

## Message

| Field | Value |
|---|---|
| From | "Vendor Weekly" &lt;news\[@\]vendor\[.\]test&gt; |
| Return-Path | bounce-77\[@\]em\[.\]vendor\[.\]test |
| To | j\*\*\*\[@\]example\[.\]com |
| Subject | Vendor Weekly: November product updates |
| Date | 2026-11-16T16:30:00+00:00 |
| Message-ID | &lt;nl-2026-11.1234\[@\]em\[.\]vendor\[.\]test&gt; |
| Origin IP | 192\[.\]0\[.\]2\[.\]71 - trust boundary \(handed to mx01\[.\]example\[.\]com\) |
| Authentication | SPF **pass** (em\[.\]vendor\[.\]test) · DKIM **pass** (vendor\[.\]test) · DMARC **pass** (policy reject) · _from mx01\[.\]example\[.\]com, trusted_ |
| Delivery path | 192\[.\]0\[.\]2\[.\]71 → mx01\[.\]example\[.\]com → mbx03\[.\]example\[.\]com · 2 s in transit |

## Indicators

| Type | Indicator (defanged) | Seen in | Reputation |
|---|---|---|---|
| ip | 192\[.\]0\[.\]2\[.\]71 | origin IP | not sent: non-routable or documentation range \(sanitized\) |

## Recommended actions

1. Close as low risk with a short note to the reporter.
2. Escalate manually if the reporter describes something not captured here (call-back number, QR code, prior thread).

## Analyst notes

- Not sent to external sources: 1 × non-routable or documentation range \(sanitized\).
- 11 indicator(s) matched local allowlist entries (cdn\[.\]vendor\[.\]test, em\[.\]vendor\[.\]test, updates\[.\]vendor\[.\]test, vendor\[.\]test); listed in `report.json` and `iocs.csv`.
- No external requests were made (offline run).
- Companion files: `report.json` (full detail + audit), `iocs.csv` (raw values for tooling), `hunt.kql`.
