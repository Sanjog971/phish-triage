# phish-triage

A safety-first workflow for triaging **sanitized** phishing email samples. It parses an `.eml` statically and extracts headers and indicators. It checks reputation only against sources you have approved, and writes a concise incident report plus machine-readable outputs.

- **Pure Python 3.11+ standard library.** `tldextract` is optional and is used offline only.
- **Offline by default.** Nothing leaves the host unless you pass `--online`. Even then, only approved sources are contacted, and only with eligible indicators.

```
samples/*.eml ──► parse (static) ──► extract IOCs ──► local intel ──► [--online: approved sources] ──► heuristics + score ──► report.md / report.json / iocs.csv / hunt.kql
```

---

## Safety guarantees

| Area | What the tool does / never does |
|---|---|
| Content | Never renders HTML, runs scripts, opens/executes attachments or follows links. HTML goes through the stdlib tokenizer only. |
| Attachments | Hashed (MD5/SHA-1/SHA-256) and type-sniffed **in memory**. Never written to disk. ZIP *names/flags* are listed, never extracted. |
| Network | No DNS, no URL fetching. Reputation calls only with `--online`, only to sources with `enabled = true` **and** an API key present. |
| Lookup-only | Each provider declares exact `(method, host, path-prefix)` endpoints. Anything else (submit/scan/upload endpoints, other hosts, plain HTTP, redirects) is refused by the client and logged as `blocked-by-policy`. |
| Data sharing | Email addresses are **never** sent. Internal, private-IP, RFC 2606/6761 reserved (sanitized), documentation-range IPs and free-mail infrastructure are never sent. A per-source `share` list limits which IOC types each source may receive. URLs carrying the recipient's address (plain, URL-encoded or base64) go out with query and fragment stripped. |
| Secrets | API keys are read from environment variables only. They are sent in headers (or the query string for Google Safe Browsing, as that API requires), and never written to logs, audit, cache or reports. |
| Reports | Every email-derived value is encoded before it enters `report.md` (`mdsafe.py`): hidden and bidi characters are shown as `[U+XXXX]`; URLs, domains, IPs and `@` are defanged; Markdown punctuation is escaped; `& < >` become entities. A crafted subject, display name, filename or header therefore cannot render links, images, mentions or raw HTML. This is tested with a hostile sample under CommonMark and GFM with linkify. Recipient addresses are redacted (`j***@example.com`). Raw values stay in `report.json`, `iocs.csv` and `hunt.kql` for tooling: treat them as sensitive. |
| Resource limits | Input size cap (25 MiB), MIME depth cap, text-scan caps, a per-run lookup budget, per-source rate limits, a response-size cap and timeouts. |
| Accountability | Every external request is recorded in `report.json → reputation.audit`: time, source, endpoint, defanged IOC, HTTP status and latency. |

---

## Quick start

```bash
cd phish-triage
python3 -m phish_triage analyze samples/ -o reports/        # offline triage of the 3 sample emails
python3 -m phish_triage sources                              # what is approved, keys, what each source may receive
python3 -m pytest -q                                         # 56 tests, no network needed
```

Optionally install it as a command with `pip install -e .`, which provides `phish-triage …`.

The bundled samples show three outcomes:

| Sample | Verdict | Why |
|---|---|---|
| `01_credential_phish_internal_spoof.eml` | MALICIOUS | Own domain spoofed (DMARC fail) and an injected fake `Authentication-Results: pass`. A Safe Links-wrapped link hides a homoglyph domain whose link text shows a different domain. Replies go to a free-mail address. Local intel hit. |
| `02_reported_html_attachment.eml` | LIKELY MALICIOUS | A user-reported message, unwrapped automatically. The attachment `.pdf.html` holds a password form pre-filled with the victim's address plus loader traits. It passes SPF/DKIM/DMARC, which does not make it safe. |
| `03_benign_vendor_newsletter.eml` | LOW RISK | Authenticated newsletter from an allowlisted vendor. |

---

## Triage runbook

### 0. One-time setup

1. **Organization profile** (`config/triage.toml → [organization]`):
   - `internal_domains`: your accepted domains.
   - `protected_domains` and `protected_display_names`: your domains plus brands that attackers imitate to your users.
   - `trusted_authserv_ids`: the authserv-id your MTA writes in `Authentication-Results`, e.g. `["mx*.yourco.com"]`. **Microsoft 365 omits the authserv-id, so use `["topmost"]` there.**
   - `trusted_mta_hosts`: your gateways and MTAs, e.g. `["*.protection.outlook.com", "*.outlook.com"]`. These locate the trust-boundary IP, which is the last IP your own infrastructure actually saw. Received headers below that point can be forged.

   Leaving the two trust lists empty still works. The report then marks authentication and origin IP as **UNVERIFIED**.
2. **Approve sources.** Do a data-sharing review per source, then set `enabled = true` and trim `share` to the indicator types policy allows. Provide keys as environment variables or through your secret manager, never in the file. Then run `phish-triage sources` to confirm.

   | Source | Key env var | Can receive | Notes |
   |---|---|---|---|
   | VirusTotal v3 | `VT_API_KEY` | url, domain, ip, sha256 | GET lookups only, never submits. Public API: 4 req/min. Domain lookups add domain age. |
   | AbuseIPDB v2 | `ABUSEIPDB_API_KEY` | ip | `/check` only |
   | URLhaus | `ABUSECH_AUTH_KEY` | url, domain, ip, sha256 | Requires an abuse.ch Auth-Key |
   | ThreatFox | `ABUSECH_AUTH_KEY` | url, domain, ip, sha256 | `search_ioc` / `search_hash` only |
   | MalwareBazaar | `ABUSECH_AUTH_KEY` | sha256 | `get_info` only, never downloads samples |
   | Google Safe Browsing v4 | `GSB_API_KEY` | url | Lookup API. Google's terms restrict it to non-commercial use. |
   | `local_intel` | n/a | everything (stays local) | `config/local_intel.csv`: your own verdicts, always consulted |

3. **Seed local intel** with your past cases and allowlisted vendors. Each row has `type,value,verdict,note`. Domain rows also match their subdomains and URLs.

### 1. Intake and safe handling

- Obtain the message as **`.eml`**. When a user reports a message with the report button or forwards it as an attachment, the reported email is analyzed and the reporter envelope is recorded. Convert `.msg` files first, e.g. with `msgconvert` (libemail-outlook-message-perl).
- Never open samples in a mail client or browser. Never click links or open attachments. Handle unsanitized originals only on an isolated analysis VM.
- Before samples leave the SOC, sanitize them by replacing recipients, tokens and internal hosts with reserved values: `example.com`, `.test`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. The tool recognizes these values and never sends them out.

### 2. Static triage (offline, default)

```bash
phish-triage analyze case-123.eml -o reports/ --case-id IR-2026-123
```

This writes `reports/IR-2026-123/` containing `report.md`, `report.json`, `iocs.csv` and `hunt.kql`.

### 3. Review the report

Spend about two minutes checking:
- **Authentication** says *trusted*. If it says UNVERIFIED, finish step 0.
- **Origin IP** says *trust boundary*. An earliest-hop IP is only a sender claim.
- **Key findings**: does the evidence hold up? Heuristics are leads, not proof.
- **Indicators**: unwrapped links (Safe Links, Proofpoint v2/v3, Barracuda and Google redirects are decoded offline). Watch for a *carries recipient ID* marker, which means a personalised lure.

### 4. Enrich with approved sources (optional)

```bash
export VT_API_KEY=… ABUSECH_AUTH_KEY=…
phish-triage analyze case-123.eml -o reports/ --online                 # all approved + keyed sources
phish-triage analyze case-123.eml -o reports/ --online --sources urlhaus,threatfox --max-lookups 20
```

Results are cached for 24 h in `.triage-cache/`, which saves quota on campaigns. Pass `--no-cache` to force fresh lookups.

### 5. Decide and respond

| Verdict | Meaning | Default response |
|---|---|---|
| **MALICIOUS** | An approved source confirms at least one indicator | Purge all copies, block indicators, scope clicks, replies and attachment opens, run the credential-compromise playbook if needed |
| **LIKELY MALICIOUS** | Score ≥ 60 from heuristics, no reputation confirmation | Same as above. Confidence is *high* when 3 or more high-severity signals agree. |
| **SUSPICIOUS** | Score 30–59 | Quarantine, verify with the sender out-of-band, use an approved sandbox if needed |
| **LOW RISK** | Score < 30 | Close with a note to the reporter. This is **not** a clearance. |

The report's *Recommended actions* section is tailored to the findings, e.g. DMARC hardening for an own-domain spoof, Reply-To checks for BEC, or endpoint triage for risky attachments.

### 6. Scope (hunt)

`hunt.kql` holds Microsoft Defender XDR advanced-hunting queries: delivery scope, same sending IP, link delivery, Safe Links clicks, attachment hashes on mail and endpoints, and replies to the Reply-To address. The values in it are **live**, so review before running.

### 7. Close

Attach `report.md` to the ticket and feed `report.json` to SOAR/SIEM (schema `phish-triage/report/v1`). Push reviewed rows of `iocs.csv` to blocklists, and add confirmed verdicts to `local_intel.csv`.

---

## What gets checked

**Headers.** SPF, DKIM, DMARC and compauth come from the *trusted* `Authentication-Results` header. Untrusted headers that claim `pass` are flagged as injection. The tool also checks for own-domain spoofing from external origins, display-name address and brand spoofing, and lookalike sender domains (homoglyph or punycode, typosquat, TLD swap, embedded brand). It compares Reply-To (including free-mail diversion), Return-Path and Message-ID against From, and looks for Received time and Date anomalies.

**Links.** Wrapped links are unwrapped. Flags cover link text that shows a different domain than the target, lookalike domains, IP literals, `user@host` tricks, punycode, non-standard ports, shorteners, free hosting and IPFS, `javascript:`/`data:` schemes, and recipient tokens embedded in URLs.

**Content.** Credential forms in bodies or attachments, forms pre-filled with the victim's address, scripts, HTML-smuggling and exfil traits (`atob`, Blob URLs, `<a download>`, `fetch`…), meta-refresh redirects, and image-only bodies that may hide a QR code.

**Attachments.** Executables and scripts, disk images (ISO/IMG/VHD), OneNote files, HTML/SVG, macros (OOXML `vbaProject.bin`, OLE VBA markers), decoy double extensions, RTLO tricks, mismatches between extension and actual content, and encrypted or risky archives.

Scoring is a capped sum of finding weights (see `heuristics.py`). Only a reputation confirmation can produce **MALICIOUS**. To tune, adjust weights and terms in the code or config, then re-run the tests.

## Limitations

- `.eml` only. QR codes inside images are flagged but not decoded. No WHOIS or newly-registered-domain checks offline; domain age comes from VirusTotal when approved. No dynamic detonation, which belongs in an approved sandbox.
- Without `tldextract`, registrable domains use a built-in suffix list that covers common multi-label and hosting suffixes. Install `tldextract` for full Public Suffix List accuracy; it uses the bundled snapshot and never downloads.
- OLE macro detection is a marker heuristic; confirm with `olevba`. Heuristic findings need analyst judgement.

## Extending

To add a source:
1. Subclass `Provider` in `phish_triage/reputation/providers.py`.
2. Declare `supports`, the exact lookup `endpoints` and `default_key_env`, and implement `_lookup()` to return a `RepResult`.
3. Register the class in `REGISTRY` and add a `[sources.<name>]` block to the config.

The client automatically enforces the endpoint allowlist, audit logging and key redaction.

## Layout

```
phish_triage/   mdsafe.py · parse.py · htmlscan.py · urls.py · domains.py · indicators.py · heuristics.py · scoring.py
                report.py · hunt.py · analysis.py · cli.py · safety.py · config.py
                reputation/  http.py (policy client) · providers.py · engine.py (gates, cache, budget, audit)
config/         triage.toml · local_intel.csv
samples/        3 sanitized .eml samples      tests/   pytest suite (mocked transport, no network)
examples/       reports/ generated from the samples (offline run)
```
