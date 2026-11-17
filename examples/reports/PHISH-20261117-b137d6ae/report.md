# Phishing triage report - PHISH-20261117-b137d6ae

| | |
|---|---|
| **Verdict** | **MALICIOUS** - score 100/100, confidence high |
| **Sample** | 01\_credential\_phish\_internal\_spoof\[.\]eml · SHA-256 `b137d6ae81cd6ad1e28e545cfc5cb772c47cf73f586c379e1114eb1d7a3b59bf` |
| **Analyzed** | 2026-11-17 10:21 UTC · phish-triage 1.0.0 |
| **Reputation** | offline \(local intel only; no external requests\) |

## Summary

Confirmed malicious: at least one indicator is flagged by an approved reputation source. Assessment: credential phishing, sender spoofing / impersonation. Key signals: Indicator flagged malicious by an approved source; Own domain spoofed by an external sender; Link domain imitates a protected domain; DMARC failed.

## Key findings

| Severity | Finding | Evidence |
|---|---|---|
| HIGH | Indicator flagged malicious by an approved source | hxxps://examp1e-sso\[.\]test/owa/auth?uid=REDACTED#\[recipient-id\] - local\_intel: Internal TI: M365 credential-harvest kit \(case…; examp1e-sso\[.\]test - local\_intel: Internal TI: M365 credential-harvest kit \(case PHISH-2026-0412\) |
| HIGH | Own domain spoofed by an external sender | From example\[.\]com arrived from 203\[.\]0\[.\]113\[.\]45; DMARC=fail |
| HIGH | Link domain imitates a protected domain | examp1e-sso\[.\]test: embedded-homoglyph of example\[.\]com |
| HIGH | DMARC failed | header\[.\]from=example\[.\]com, policy=quarantine |
| HIGH | Link text shows a different domain than its target | text 'portal\[.\]example\[.\]com' -&gt; examp1e-sso\[.\]test |
| HIGH | Replies are diverted to a free-mail account | From example\[.\]com -&gt; Reply-To it.servicedesk.verify\[@\]freemail\[.\]test |
| MEDIUM | Untrusted Authentication-Results header claims 'pass' | mail\[.\]bulk-sender\[.\]test claims pass; your MTA \(mx01\[.\]example\[.\]com\) says dmarc=fail |
| MEDIUM | Link points to a raw IP address | hxxp://203\[.\]0\[.\]113\[.\]77:8080/keep-password/ |

_5 more finding(s) in report.json._

## Message

| Field | Value |
|---|---|
| From | "Example Corp IT Service Desk" &lt;servicedesk\[@\]example\[.\]com&gt; |
| Reply-To | "IT Service Desk" &lt;it.servicedesk.verify\[@\]freemail\[.\]test&gt; |
| Return-Path | bounce+7f3a\[@\]mailer\[.\]bulk-sender\[.\]test |
| To | j\*\*\*\[@\]example\[.\]com |
| Subject | Action required: your mailbox password expires today |
| Date | 2026-11-17T08:12:01+00:00 |
| Message-ID | &lt;20261117081201.4471.servicedesk\[@\]mailer\[.\]bulk-sender\[.\]test&gt; |
| Origin IP | 203\[.\]0\[.\]113\[.\]45 - trust boundary \(handed to mx01\[.\]example\[.\]com\) |
| Authentication | SPF **pass** (mailer\[.\]bulk-sender\[.\]test) · DKIM **none** · DMARC **fail** (policy quarantine) · _from mx01\[.\]example\[.\]com, trusted_ |
| Delivery path | 198\[.\]51\[.\]100\[.\]200 → mail\[.\]bulk-sender\[.\]test → mx01\[.\]example\[.\]com → mbx03\[.\]example\[.\]com · 6 s in transit |

## Indicators

| Type | Indicator (defanged) | Seen in | Reputation |
|---|---|---|---|
| url | hxxps://examp1e-sso\[.\]test/owa/auth?uid=REDACTED#\[recipient-id\] | text body, HTML a\[.\]href \(unwrapped microsoft-safelinks\) - carries recipient ID | local\_intel: **malicious** - Internal TI: M365 credential-harvest kit \(case PHISH-2026-0412\) \(via domain… |
| url | hxxp://203\[.\]0\[.\]113\[.\]77:8080/keep-password/ | text body, HTML a\[.\]href | not sent: non-routable or documentation range \(sanitized\) |
| url | hxxps://cdn\[.\]bulk-sender\[.\]test/o\[.\]gif?r=REDACTED | HTML img\[.\]src | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| domain | mailer\[.\]bulk-sender\[.\]test | Return-Path | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| domain | examp1e-sso\[.\]test | link host | local\_intel: **malicious** - Internal TI: M365 credential-harvest kit \(case PHISH-2026-0412\) |
| domain | cdn\[.\]bulk-sender\[.\]test | link host | not sent: reserved/sanitized name \(RFC 2606/6761\) |
| ip | 203\[.\]0\[.\]113\[.\]45 | origin IP | not sent: non-routable or documentation range \(sanitized\) |
| ip | 198\[.\]51\[.\]100\[.\]200 | earliest Received hop | not sent: non-routable or documentation range \(sanitized\) |
| ip | 203\[.\]0\[.\]113\[.\]77 | link host | not sent: non-routable or documentation range \(sanitized\) |
| email | it.servicedesk.verify\[@\]freemail\[.\]test | Reply-To | not sent: email addresses are never sent externally |
| email | bounce+7f3a\[@\]mailer\[.\]bulk-sender\[.\]test | Return-Path | not sent: email addresses are never sent externally |

## Recommended actions

1. **Contain** - search and purge every copy (same Message-ID, or sender + subject); see `hunt.kql` §1.
2. **Block** - 6 URL/domain indicator(s) at web proxy, DNS filter and mail gateway (`iocs.csv`).
3. **Harden** - example\[.\]com is being spoofed: confirm DMARC is `p=quarantine`/`reject` and enforced at the gateway.
4. **Scope exposure** - identify recipients who clicked or opened the lure (`hunt.kql` §1, §4). For anyone who entered credentials: reset password, revoke sessions/refresh tokens, review MFA methods, inbox rules and sign-in logs.
5. **Check replies** - look for outbound mail to the Reply-To address (`hunt.kql` §6); treat any reply as possible data or payment exposure.
6. **Close the loop** - thank the reporter, warn recipients, and share IOCs with your intel platform per policy.

## Analyst notes

- Ignored 1 Authentication-Results header(s) not written by a trusted MTA: mail\[.\]bulk-sender\[.\]test.
- Earliest Received hop claims 198\[.\]51\[.\]100\[.\]200 (sender-side, unverified).
- Not sent to external sources: 5 × reserved/sanitized name \(RFC 2606/6761\); 4 × non-routable or documentation range \(sanitized\).
- No external requests were made (offline run).
- Companion files: `report.json` (full detail + audit), `iocs.csv` (raw values for tooling), `hunt.kql`.
