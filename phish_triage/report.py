"""Report writers: concise Markdown for humans, JSON for SOAR/SIEM, CSV for blocklists."""
from __future__ import annotations

import csv
import dataclasses
import io
import json
from datetime import datetime
from pathlib import Path

from .analysis import AnalysisResult
from .config import domain_in
from .hunt import build_kql
from .mdsafe import md_text as M
from .safety import defang, redact_address

MAX_FINDINGS = 8
MAX_IOCS = 15
VERDICT_LEAD = {
    "MALICIOUS": "Confirmed malicious: at least one indicator is flagged by an approved reputation source.",
    "LIKELY MALICIOUS": "Strong phishing traits{rep}.",
    "SUSPICIOUS": "Phishing traits present; analyst review required{rep}.",
    "LOW RISK": "No significant phishing traits found{rep}. Not a clearance - weigh the reporter's context.",
}


def _short(s: str, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n].rsplit(" ", 1)[0].rstrip(" ,;(") + "…"


def _addr(addr: str | None, redact: bool) -> str:
    """Raw (optionally redacted) address, defanged. Encode with M() before it enters Markdown."""
    if not addr:
        return "-"
    return defang(redact_address(addr) if redact else addr, "email")


def _fmt_address(a, redact=False) -> str:
    """Raw display form `"name" <addr>`; the caller encodes the WHOLE string with M()."""
    if a is None:
        return "-"
    name = f'"{a.display_name}" ' if a.display_name else ""
    return f"{name}<{_addr(a.addr, redact)}>"


def _rep_cell(ind) -> str:
    """Markdown cell: our markup (**, <br>) around individually encoded values."""
    parts = []
    for r in sorted(ind.reputation, key=lambda r: (r.status != "malicious", r.source)):
        s = f"{M(r.source)}: **{M(r.status.replace('_', ' '))}**"
        if r.status in ("malicious", "suspicious", "allowlisted", "error", "blocked") and r.summary:
            s += f" - {M(_short(r.summary, 80))}"
        if r.cached:
            s += " (cached)"
        parts.append(s)
    if not parts:
        if not ind.lookup_eligible:
            return M(f"not sent: {ind.skip_reason}")
        return "not checked (offline)"
    return "<br>".join(parts)


def _seen(ind) -> str:
    src = list(dict.fromkeys(ind.sources))
    s = ", ".join(src[:3]) + (f" +{len(src) - 3}" if len(src) > 3 else "")
    extra = [t.split(":", 1)[1] for t in ind.tags if t.startswith("unwrapped:")]
    if extra:
        s += f" (unwrapped {extra[0]})"
    if "recipient-identifier" in ind.tags:
        s += " - carries recipient ID"
    return s


def _path(res: AnalysisResult, internal_domains: list[str]) -> str:
    pe = res.pe
    chron = list(reversed(pe.hops))
    if not chron:
        return "-"

    def show(host):
        return host if domain_in(host, internal_domains) else defang(host or "?")

    steps = []
    first = chron[0]
    if first.from_ip:
        steps.append(defang(first.from_ip))
    elif first.from_host:
        steps.append(show(first.from_host))
    for h in chron:
        steps.append(show(h.by_host))
    stamps = [h.timestamp for h in chron if h.timestamp]
    dur = f" · {int((max(stamps) - min(stamps)).total_seconds())} s in transit" if len(stamps) > 1 else ""
    return " → ".join(steps) + dur


def _auth_line(pe) -> str:
    """Markdown: header-derived values are encoded one by one; only the emphasis is ours."""
    a = pe.auth
    if a.source == "none":
        return M(a.note or "not available")
    dkim = a.dkim_result or "none"
    dkim_d = next((d for r, d in a.dkim if r == dkim and d), None)
    bits = [f"SPF **{M(a.spf or 'none')}**" + (f" ({M(a.spf_domain)})" if a.spf_domain else ""),
            f"DKIM **{M(dkim)}**" + (f" ({M(dkim_d)})" if dkim_d else ""),
            f"DMARC **{M(a.dmarc or 'none')}**" + (f" (policy {M(a.dmarc_policy)})" if a.dmarc_policy else "")]
    if a.compauth:
        bits.append(f"compauth **{M(a.compauth)}**")
    src = f"from {M(a.authserv_id)}" if a.authserv_id else "from topmost header"
    bits.append(f"_{src}, {'trusted' if a.trusted else 'UNVERIFIED'}_")
    return " · ".join(bits)


def summary_text(res: AnalysisResult) -> str:
    v = res.verdict
    online = res.reputation_mode.startswith("online:")
    rep = "" if v.label == "MALICIOUS" else (
        "; no external reputation confirmation" if online else "; external reputation not checked (offline run)")
    lead = VERDICT_LEAD[v.label].format(rep=rep)
    out = [lead]
    if v.categories:
        out.append("Assessment: " + ", ".join(v.categories) + ".")
    top = [f.title for f in res.findings if f.severity in ("high", "medium")][:4]
    if top:
        out.append("Key signals: " + "; ".join(top) + ".")
    return " ".join(out)


def recommended_actions(res: AnalysisResult, esc=lambda s: s) -> list[str]:
    """`esc` encodes email-derived values: M() for the Markdown report, identity for JSON."""
    pe, v = res.pe, res.verdict.label
    ids = {f.id for f in res.findings}
    iocs = [i for i in res.iocs.all() if not i.hidden]
    block_net = [i for i in iocs if i.type in ("url", "domain") and "freemail" not in i.tags]
    A = []
    if v in ("MALICIOUS", "LIKELY MALICIOUS"):
        A.append("**Contain** - search and purge every copy (same Message-ID, or sender + subject); see `hunt.kql` §1.")
        if block_net:
            A.append(f"**Block** - {len(block_net)} URL/domain indicator(s) at web proxy, DNS filter and mail gateway (`iocs.csv`).")
        if any(a.detected_type != "message/rfc822" for a in pe.attachments):
            A.append("**Block** - attachment SHA-256 in EDR and the mail gateway; check endpoints for the file (`hunt.kql` §5).")
        if "INTERNAL_DOMAIN_SPOOF" in ids:
            A.append(f"**Harden** - {esc(defang(pe.from_.domain))} is being spoofed: confirm DMARC is `p=quarantine`/`reject` and enforced at the gateway.")
        elif pe.from_ and pe.from_.domain:
            from_ind = res.iocs.get("domain", pe.from_.domain)
            if from_ind is not None and "freemail" in from_ind.tags:
                A.append(f"**Block sender** - the address {esc(_addr(pe.from_.addr, False))} (free-mail domain: block the address, not the domain).")
            else:
                A.append(f"**Block sender** - {esc(defang(pe.from_.domain))} (first rule out a compromised legitimate partner).")
        if ids & {"CREDENTIAL_FORM", "LINK_TEXT_MISMATCH", "LOOKALIKE_LINK_DOMAIN", "ATTACHMENT_HTML"}:
            A.append("**Scope exposure** - identify recipients who clicked or opened the lure (`hunt.kql` §1, §4). For anyone who "
                     "entered credentials: reset password, revoke sessions/refresh tokens, review MFA methods, inbox rules and sign-in logs.")
        if ids & {"REPLY_TO_FREEMAIL", "REPLY_TO_MISMATCH"}:
            A.append("**Check replies** - look for outbound mail to the Reply-To address (`hunt.kql` §6); "
                     "treat any reply as possible data or payment exposure.")
        if ids & {"ATTACHMENT_EXECUTABLE", "ATTACHMENT_DISK_IMAGE", "ATTACHMENT_MACRO", "ATTACHMENT_ONENOTE",
                  "ATTACHMENT_ARCHIVE_RISKY"}:
            A.append("**Endpoint** - isolate and triage any host where the attachment was opened.")
        A.append("**Close the loop** - thank the reporter, warn recipients, and share IOCs with your intel platform per policy.")
    elif v == "SUSPICIOUS":
        A += ["Hold or quarantine the message while it is reviewed.",
              "Verify with the purported sender through a known-good channel (never via Reply-To).",
              "If dynamic analysis is needed, detonate only in an approved sandbox - never on an analyst workstation."]
        if not res.reputation_mode.startswith("online:"):
            A.append("Re-run with `--online` (approved sources) to add reputation context.")
    else:
        A += ["Close as low risk with a short note to the reporter.",
              "Escalate manually if the reporter describes something not captured here (call-back number, QR code, prior thread)."]
    return A


def render_markdown(res: AnalysisResult, internal_domains: list[str]) -> str:
    """Every value that is not a constant of this module goes through M() (mdsafe.md_text) at the
    point it is inserted. Our own markup (tables, **, _, <br>, `constant` code spans) is added
    around encoded values, never inside raw ones. Code spans are used only for our hex hashes and
    fixed file names: content inside a code span cannot be backslash-escaped, so untrusted text
    never goes in one."""
    pe, v, R = res.pe, res.verdict, res.redact
    L = [f"# Phishing triage report - {M(res.case_id)}", "", "| | |", "|---|---|",
         f"| **Verdict** | **{M(v.label)}** - score {int(v.score)}/100, confidence {M(v.confidence)} |",
         f"| **Sample** | {M(Path(pe.path).name)} · SHA-256 `{pe.file_sha256}` |",
         f"| **Analyzed** | {res.analyzed_at:%Y-%m-%d %H:%M} UTC · phish-triage {M(res.tool_version)} |",
         f"| **Reputation** | {M(res.reputation_mode)} |"]
    if pe.unwrapped_from:
        u = pe.unwrapped_from
        L.append(f"| **Reported by** | {M(_addr(u.get('reporter'), R))} on {M(u.get('date') or '-')} "
                 "- embedded message analyzed |")
    L += ["", "## Summary", "", M(summary_text(res)), ""]

    shown = [f for f in res.findings if f.severity != "info"][:MAX_FINDINGS]
    if shown:
        L += ["## Key findings", "", "| Severity | Finding | Evidence |", "|---|---|---|"]
        for f in shown:
            ev = "; ".join(M(_short(e, 140)) for e in f.evidence[:2])
            ev += f" (+{len(f.evidence) - 2})" if len(f.evidence) > 2 else ""
            L.append(f"| {M(f.severity.upper())} | {M(f.title)} | {ev} |")
        more = len([f for f in res.findings if f.severity != "info"]) - len(shown)
        if more > 0:
            L.append(f"\n_{more} more finding(s) in report.json._")
        L.append("")

    L += ["## Message", "", "| Field | Value |", "|---|---|",
          f"| From | {M(_fmt_address(pe.from_))} |"]
    if pe.reply_to:
        L.append(f"| Reply-To | {M(', '.join(_fmt_address(a) for a in pe.reply_to))} |")
    L += [f"| Return-Path | {M(_addr(pe.return_path, False))} |",
          f"| To | {M(', '.join(_addr(a.addr, R) for a in pe.to) or '-')} |",
          f"| Subject | {M(pe.subject) or '-'} |",
          f"| Date | {M(pe.date.isoformat() if pe.date else pe.date_raw or '-')} |",
          f"| Message-ID | {M(pe.message_id or '-')} |",
          f"| Origin IP | {M(pe.origin_ip or '-')} - {M(pe.origin_method)} |",
          f"| Authentication | {_auth_line(pe)} |",
          f"| Delivery path | {M(_path(res, internal_domains))} |", ""]

    visible = [i for i in res.iocs.all() if not i.hidden]
    allowlisted = [i for i in visible if i.worst_status == "allowlisted"]
    visible = [i for i in visible if i.worst_status != "allowlisted"]
    if visible:
        L += ["## Indicators", "", "| Type | Indicator (defanged) | Seen in | Reputation |", "|---|---|---|---|"]
        for ind in visible[:MAX_IOCS]:
            L.append(f"| {M(ind.type)} | {M(ind.defanged)} | {M(_seen(ind))} | {_rep_cell(ind)} |")
        if len(visible) > MAX_IOCS:
            L.append(f"\n_{len(visible) - MAX_IOCS} more indicator(s) in iocs.csv._")
        L.append("")

    if pe.attachments:
        L += ["## Attachments", "", "| File | Declared / detected | Size | SHA-256 | Flags |", "|---|---|---|---|---|"]
        for a in pe.attachments:
            L.append(f"| {M(a.filename)} | {M(a.declared_type)} / {M(a.detected_type)} | {int(a.size):,} B "
                     f"| `{a.sha256}` | {M(', '.join(a.flags) or '-')} |")
        L.append("")

    L += ["## Recommended actions", ""] + [f"{n}. {a}" for n, a in enumerate(recommended_actions(res, M), 1)] + [""]

    notes = []
    a = pe.auth
    if a.note:
        notes.append(f"Authentication: {M(a.note)}.")
    if a.ignored:
        ids = M(", ".join(i["authserv_id"] or "(no id)" for i in a.ignored))
        notes.append(f"Ignored {len(a.ignored)} Authentication-Results header(s) not written by a trusted MTA: {ids}.")
    if pe.earliest_claimed_ip and pe.earliest_claimed_ip != pe.origin_ip:
        notes.append(f"Earliest Received hop claims {M(pe.earliest_claimed_ip)} (sender-side, unverified).")
    skipped = [i for i in visible if not i.lookup_eligible and i.type != "email"]
    if skipped:
        reasons: dict[str, int] = {}
        for i in skipped:
            reasons[i.skip_reason] = reasons.get(i.skip_reason, 0) + 1
        notes.append("Not sent to external sources: " + "; ".join(f"{n} × {M(r)}" for r, n in reasons.items()) + ".")
    if allowlisted:
        hosts = sorted({i.meta.get("host") or i.value.rpartition("@")[2] for i in allowlisted})[:4]
        notes.append(f"{len(allowlisted)} indicator(s) matched local allowlist entries ({M(', '.join(hosts))}); "
                     "listed in `report.json` and `iocs.csv`.")
    if res.audit:
        errs = sum(1 for e in res.audit if not isinstance(e["status"], int) or e["status"] >= 400)
        notes.append(f"{len(res.audit)} external lookup request(s) made ({errs} failed/blocked); full audit trail in `report.json`.")
    elif res.reputation_mode.startswith("offline"):
        notes.append("No external requests were made (offline run).")
    for src in res.sources:
        if not src["ready"] and src["source"] != "local_intel" and "not approved" not in src["detail"] \
                and "offline" not in src["detail"]:
            notes.append(f"Source {M(src['source'])} skipped: {M(src['detail'])}.")
    notes += [M(n) for n in res.notes]
    if pe.defects:
        notes.append(f"Parser noted MIME defects: {M(', '.join(sorted(set(pe.defects))))}.")
    notes.append("Companion files: `report.json` (full detail + audit), `iocs.csv` (raw values for tooling), `hunt.kql`.")
    L += ["## Analyst notes", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(L)


# ------------------------------------------------------------------------- JSON / CSV

def _jsonable(o):
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(o).items()}
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_jsonable(v) for v in o]
    if isinstance(o, datetime):
        return o.isoformat()
    return o


def to_json(res: AnalysisResult) -> dict:
    pe, R = res.pe, res.redact
    red = (lambda a: redact_address(a) if R and a else a)
    atts = []
    for a in pe.attachments:
        d = {k: getattr(a, k) for k in ("filename", "declared_type", "detected_type", "size", "md5", "sha1",
                                         "sha256", "disposition", "archive_entries", "archive_encrypted",
                                         "has_macros", "flags")}
        if a.html:
            d["html"] = {"forms": a.html.forms, "password_inputs": a.html.password_inputs,
                         "scripts": a.html.scripts, "js_traits": a.html.js_traits,
                         "meta_refresh": a.html.meta_refresh}
        atts.append(d)
    return _jsonable({
        "schema": "phish-triage/report/v1",
        "case_id": res.case_id, "analyzed_at": res.analyzed_at, "tool_version": res.tool_version,
        "verdict": {"label": res.verdict.label, "score": res.verdict.score,
                    "confidence": res.verdict.confidence, "categories": res.verdict.categories,
                    "summary": summary_text(res)},
        "sample": {"file": Path(pe.path).name, "sha256": pe.file_sha256, "size": pe.size,
                   "reported_by": ({**pe.unwrapped_from, "reporter": red(pe.unwrapped_from.get("reporter"))}
                                   if pe.unwrapped_from else None)},
        "message": {
            "from": {"display_name": pe.from_.display_name, "address": pe.from_.addr} if pe.from_ else None,
            "reply_to": [a.addr for a in pe.reply_to], "return_path": pe.return_path,
            "to": [red(a.addr) for a in pe.to], "cc": [red(a.addr) for a in pe.cc],
            "subject": pe.subject, "date": pe.date or pe.date_raw, "message_id": pe.message_id,
            "origin_ip": pe.origin_ip, "origin_method": pe.origin_method,
            "earliest_claimed_ip": pe.earliest_claimed_ip, "x_originating_ip": pe.x_originating_ip,
            "authentication": pe.auth, "dkim_signatures": pe.dkim_signatures,
            "received_hops_newest_first": pe.hops,
            "body_parts": {"text": len(pe.text_bodies), "html": len(pe.html_bodies)},
        },
        "findings": res.findings,
        "indicators": [{"type": i.type, "value": i.value, "display": i.display, "defanged": i.defanged,
                        "sources": i.sources, "tags": i.tags, "lookup_eligible": i.lookup_eligible,
                        "skip_reason": i.skip_reason, "wrapped_forms": i.wrapped, "meta": i.meta,
                        "reputation": [r.to_dict() for r in i.reputation]} for i in res.iocs.all()],
        "attachments": atts,
        "recommended_actions": recommended_actions(res),
        "reputation": {"mode": res.reputation_mode, "sources": res.sources, "audit": res.audit},
        "notes": res.notes,
    })


def to_csv(res: AnalysisResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "worst_status", "sources", "tags", "lookup_eligible", "skip_reason",
                "reputation"])
    for i in res.iocs.all():
        if "internal" in i.tags or "benign-infrastructure" in i.tags:
            continue
        w.writerow([i.type, i.value, i.defanged, i.worst_status or "", "; ".join(i.sources), "; ".join(i.tags),
                    i.lookup_eligible, i.skip_reason or "",
                    "; ".join(f"{r.source}:{r.status}" for r in i.reputation)])
    return buf.getvalue()


def write_outputs(res: AnalysisResult, outdir: Path, internal_domains: list[str], formats: set[str]) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    written = {}
    if "md" in formats:
        p = outdir / "report.md"
        p.write_text(render_markdown(res, internal_domains), encoding="utf-8")
        written["md"] = p
    if "json" in formats:
        p = outdir / "report.json"
        p.write_text(json.dumps(to_json(res), indent=2, ensure_ascii=False), encoding="utf-8")
        written["json"] = p
    if "csv" in formats:
        p = outdir / "iocs.csv"
        p.write_text(to_csv(res), encoding="utf-8")
        written["csv"] = p
    if "kql" in formats:
        p = outdir / "hunt.kql"
        p.write_text(build_kql(res.case_id, res.pe, res.iocs), encoding="utf-8")
        written["kql"] = p
    return written
