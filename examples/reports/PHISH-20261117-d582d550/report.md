# Phishing triage report - PHISH-20261117-d582d550

| | |
|---|---|
| **Verdict** | **LIKELY MALICIOUS** - score 100/100, confidence medium |
| **Sample** | 02\_reported\_html\_attachment\[.\]eml · SHA-256 `d582d550a1ee9bfae343b0daa639914ad3e78285f125fe71cc9a1df80a0ad167` |
| **Analyzed** | 2026-11-17 10:21 UTC · phish-triage 1.0.0 |
| **Reputation** | offline \(local intel only; no external requests\) |
| **Reported by** | j\*\*\*\[@\]example\[.\]com on Tue, 17 Nov 2026 09:01:44 +0000 - embedded message analyzed |

## Summary

Strong phishing traits; external reputation not checked \(offline run\). Assessment: malware delivery, credential phishing. Key signals: Attachment uses a decoy double extension; HTML form collects a password; HTML/SVG attachment \(credential page or smuggling\); HTML attachment contains loader/exfil script traits.

## Key findings

| Severity | Finding | Evidence |
|---|---|---|
| HIGH | Attachment uses a decoy double extension | Remittance\_Advice\_44817\[.\]pdf\[.\]html |
| HIGH | HTML form collects a password | attachment Remittance\_Advice\_44817\[.\]pdf\[.\]html: posts to hxxps://collect\[.\]invoice-portal\[.\]test/rx/submit\[.\]php |
| MEDIUM | HTML/SVG attachment \(credential page or smuggling\) | Remittance\_Advice\_44817\[.\]pdf\[.\]html |
| MEDIUM | HTML attachment contains loader/exfil script traits | attachment Remittance\_Advice\_44817\[.\]pdf\[.\]html: base64 decoding \(atob\) |
| MEDIUM | Indicator flagged suspicious by an approved source | 198\[.\]51\[.\]100\[.\]23 - local\_intel: Seen in prior invoice-fraud attempts \(case PHISH-2026-0377\) |
| MEDIUM | Form is pre-filled with the recipient's address | attachment Remittance\_Advice\_44817\[.\]pdf\[.\]html: targeted kit \(personalised per victim\) |
| LOW | Urgency / credential-lure language | sign in with your email |

## Message

| Field | Value |
|---|---|
| From | "Accounts Payable" &lt;ap\[@\]northwind-billing\[.\]test&gt; |
| Return-Path | ap\[@\]northwind-billing\[.\]test |
| To | j\*\*\*\[@\]example\[.\]com |
| Subject | Remittance advice #44817 - payment released |
| Date | 2026-11-16T14:03:05+00:00 |
| Message-ID | &lt;a1b2c3d4.44817\[@\]northwind-billing\[.\]test&gt; |
| Origin IP | 198\[.\]51\[.\]100\[.\]23 - trust boundary \(handed to mx02\[.\]example\[.\]com\) |
| Authentication | SPF **pass** (northwind-billing\[.\]test) · DKIM **pass** (northwind-billing\[.\]test) · DMARC **pass** (policy none) · _from mx02\[.\]example\[.\]com, trusted_ |
| Delivery path | 198\[.\]51\[.\]100\[.\]23 → mx02\[.\]example\[.\]com → mbx01\[.\]example\[.\]com · 2 s in transit |

## Indicators

| Type | Indicator (defanged) | Seen in | Reputation |
|---|---|---|---|
| url | hxxps://collect\[.\]invoice-portal\[.\]test/rx/submit\[.\]php | attachment Remittance\_Advice\_44817\[.\]pdf\[.\]html \(form\[.\]action\) | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| domain | northwind-billing\[.\]test | From, Return-Path | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| domain | collect\[.\]invoice-portal\[.\]test | link host | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| ip | 198\[.\]51\[.\]100\[.\]23 | origin IP | local\_intel: **suspicious** - Seen in prior invoice-fraud attempts \(case PHISH-2026-0377\) |
| sha256 | 89e8321b45989ff9121e351961bf68be7efcb2c596c5841a19b17ff7bf95daba | attachment Remittance\_Advice\_44817\[.\]pdf\[.\]html | not checked (offline) |
| email | ap\[@\]northwind-billing\[.\]test | From, Return-Path | not sent: email addresses are never sent externally |

## Attachments

| File | Declared / detected | Size | SHA-256 | Flags |
|---|---|---|---|---|
| Remittance\_Advice\_44817\[.\]pdf\[.\]html | text/html / html | 539 B | `89e8321b45989ff9121e351961bf68be7efcb2c596c5841a19b17ff7bf95daba` | HTML/SVG, double extension |

## Recommended actions

1. **Contain** - search and purge every copy (same Message-ID, or sender + subject); see `hunt.kql` §1.
2. **Block** - 3 URL/domain indicator(s) at web proxy, DNS filter and mail gateway (`iocs.csv`).
3. **Block** - attachment SHA-256 in EDR and the mail gateway; check endpoints for the file (`hunt.kql` §5).
4. **Block sender** - northwind-billing\[.\]test (first rule out a compromised legitimate partner).
5. **Scope exposure** - identify recipients who clicked or opened the lure (`hunt.kql` §1, §4). For anyone who entered credentials: reset password, revoke sessions/refresh tokens, review MFA methods, inbox rules and sign-in logs.
6. **Close the loop** - thank the reporter, warn recipients, and share IOCs with your intel platform per policy.

## Analyst notes

- Not sent to external sources: 3 × reserved/sanitized name \(RFC 2606/6761\); 1 × non-routable or documentation range \(sanitized\).
- No external requests were made (offline run).
- Companion files: `report.json` (full detail + audit), `iocs.csv` (raw values for tooling), `hunt.kql`.
