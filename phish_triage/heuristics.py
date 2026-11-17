"""Phishing heuristics. Each rule adds a weighted Finding with human-readable evidence."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

from .config import Config, domain_in
from .domains import lookalike, same_org
from .indicators import EMAIL_RX, IndicatorSet
from .parse import ParsedEmail
from .safety import defang, is_internal_ip, refang
from .urls import normalize_url, unwrap_url, url_parts

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

EXEC_EXTS = {"exe", "scr", "com", "pif", "cpl", "dll", "msi", "msp", "bat", "cmd", "ps1", "psm1",
             "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "reg", "chm", "url",
             "scf", "appx", "msix", "appinstaller", "application", "xll", "iqy", "slk",
             "settingcontent-ms", "library-ms", "search-ms"}
DISK_IMAGE_EXTS = {"iso", "img", "vhd", "vhdx", "udf"}
ONENOTE_EXTS = {"one", "onepkg"}
MACRO_EXTS = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
HTML_EXTS = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "arj", "cab", "xz", "bz2", "z", "lzh", "uue"}
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg",
              "jpeg", "png", "gif", "zip", "mp3", "mp4", "wav", "eml", "msg", "odt"}
EXPECTED_TYPES = {
    "pdf": {"pdf"}, "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"}, "docm": {"ooxml"},
    "xlsm": {"ooxml"}, "pptm": {"ooxml"}, "doc": {"ole2", "rtf"}, "xls": {"ole2"}, "ppt": {"ole2"},
    "msg": {"ole2"}, "msi": {"ole2"}, "zip": {"zip", "ooxml", "jar", "odf"}, "jar": {"jar", "zip"},
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"}, "tgz": {"gzip"}, "exe": {"pe-executable"},
    "dll": {"pe-executable"}, "scr": {"pe-executable"}, "png": {"png"}, "jpg": {"jpeg"},
    "jpeg": {"jpeg"}, "gif": {"gif"}, "tif": {"tiff"}, "tiff": {"tiff"}, "html": {"html", "text"},
    "htm": {"html", "text"}, "svg": {"svg", "xml"}, "txt": {"text"}, "csv": {"text"},
    "rtf": {"rtf"}, "iso": {"iso9660"}, "lnk": {"lnk"}, "cab": {"cab"},
}


@dataclass
class Finding:
    id: str
    severity: str
    weight: int
    title: str
    evidence: list = field(default_factory=list)


class Findings:
    def __init__(self):
        self._d: dict[str, Finding] = {}

    def add(self, id_: str, severity: str, weight: int, title: str, evidence: str):
        f = self._d.get(id_)
        if f is None:
            self._d[id_] = Finding(id_, severity, weight, title, [evidence])
        elif evidence not in f.evidence and len(f.evidence) < 6:
            f.evidence.append(evidence)

    def has(self, *ids: str) -> bool:
        return any(i in self._d for i in ids)

    def list(self) -> list[Finding]:
        return sorted(self._d.values(), key=lambda f: (SEV_ORDER[f.severity], -f.weight, f.id))


def _anchor_shown_host(text: str) -> str | None:
    t = refang(text or "").strip()
    if not t or EMAIL_RX.fullmatch(t):
        return None
    m = re.search(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?=[/:?#\s]|$)", t)
    return m.group(1).lower() if m else None


def _href_host(href: str) -> str | None:
    n = normalize_url(href)
    if not n:
        return None
    final, chain = unwrap_url(n)
    final = normalize_url(final) if chain else n
    return url_parts(final).host if final else None


def evaluate(pe: ParsedEmail, iocs: IndicatorSet, cfg: Config) -> list[Finding]:
    F = Findings()
    org, an = cfg.org, cfg.analysis
    internal, protected = org["internal_domains"], org["protected_domains"]
    freemail = an["freemail_domains"]
    from_dom = pe.from_.domain if pe.from_ else ""
    auth = pe.auth
    origin_external = bool(pe.origin_ip and not is_internal_ip(pe.origin_ip))

    # ------------------------------------------------------------ authentication
    if auth.source == "none":
        F.add("AUTH_RESULTS_MISSING", "info", 0, "No usable Authentication-Results header",
              auth.note or "SPF/DKIM/DMARC verdicts not available (headers stripped or untrusted)")
    else:
        if auth.dmarc in ("fail", "permerror"):
            F.add("DMARC_FAIL", "high", 25, "DMARC failed",
                  f"header.from={defang(auth.dmarc_from or from_dom)}, policy={auth.dmarc_policy or 'n/a'}")
        if auth.spf in ("fail", "permerror"):
            F.add("SPF_FAIL", "medium", 15, "SPF failed", f"envelope domain {defang(auth.spf_domain or '?')}")
        elif auth.spf == "softfail":
            F.add("SPF_SOFTFAIL", "low", 8, "SPF soft-failed", f"envelope domain {defang(auth.spf_domain or '?')}")
        dk = auth.dkim_result
        if dk in ("fail", "permerror"):
            F.add("DKIM_FAIL", "medium", 10, "DKIM signature failed verification", f"d={auth.dkim[0][1] or '?'}")
        elif dk in (None, "none") and auth.dmarc != "pass":
            F.add("DKIM_NONE", "low", 3, "Message not DKIM-signed", "no valid DKIM signature")
        if auth.trusted and auth.ignored:
            claims = [i for i in auth.ignored if "pass" in (i.get("dmarc"), i.get("spf"), i.get("dkim"))]
            if claims and (auth.dmarc != "pass"):
                ids = ", ".join(defang(i["authserv_id"] or "(no authserv-id)") for i in claims)
                F.add("AUTH_HEADER_INJECTION", "medium", 15,
                      "Untrusted Authentication-Results header claims 'pass'",
                      f"{ids} claims pass; your MTA ({auth.authserv_id}) says dmarc={auth.dmarc}")

    # ------------------------------------------------------------ sender identity
    if from_dom and domain_in(from_dom, internal) and origin_external:
        if auth.source != "none" and auth.dmarc != "pass":
            F.add("INTERNAL_DOMAIN_SPOOF", "high", 35, "Own domain spoofed by an external sender",
                  f"From {defang(from_dom)} arrived from {defang(pe.origin_ip)}; DMARC={auth.dmarc or 'none'}")
        elif auth.source == "none":
            F.add("INTERNAL_DOMAIN_EXTERNAL_ORIGIN", "medium", 15, "Own domain used by external origin",
                  f"From {defang(from_dom)} arrived from {defang(pe.origin_ip)} (no auth results to confirm)")

    if pe.from_:
        dn = pe.from_.display_name or ""
        for e in EMAIL_RX.findall(dn):
            if not same_org(e.rpartition("@")[2], from_dom):
                F.add("DISPLAY_NAME_ADDRESS_SPOOF", "high", 25, "Display name shows a different email address",
                      f'"{defang(dn, "email")}" but sent from {defang(pe.from_.addr, "email")}')
        legit = protected + internal
        for brand in org["protected_display_names"]:
            if brand.lower() in dn.lower() and not domain_in(from_dom, legit):
                F.add("DISPLAY_NAME_BRAND", "medium", 15, "Display name impersonates a protected brand",
                      f'"{dn}" sent from {defang(from_dom)}')
                break

    for dom, label in [(from_dom, "From")] + [(a.domain, "Reply-To") for a in pe.reply_to] + \
            [((pe.return_path or "").rpartition("@")[2], "Return-Path")]:
        if not dom or domain_in(dom, internal):
            continue
        hit = lookalike(dom, protected)
        if hit:
            sev, w = ("medium", 20) if hit["kind"] == "embedded-brand" else ("high", 30)
            F.add("LOOKALIKE_SENDER_DOMAIN", sev, w, "Sender domain imitates a protected domain",
                  f"{label} {defang(dom)}: {hit['kind']} of {hit['target']}")

    for rt in pe.reply_to:
        if rt.domain and from_dom and not same_org(rt.domain, from_dom):
            if domain_in(rt.domain, freemail):
                F.add("REPLY_TO_FREEMAIL", "high", 20, "Replies are diverted to a free-mail account",
                      f"From {defang(from_dom)} -> Reply-To {defang(rt.addr, 'email')}")
            else:
                F.add("REPLY_TO_MISMATCH", "medium", 12, "Reply-To domain differs from From domain",
                      f"From {defang(from_dom)} -> Reply-To {defang(rt.domain)}")

    rp_dom = (pe.return_path or "").rpartition("@")[2]
    if rp_dom and from_dom and not same_org(rp_dom, from_dom):
        F.add("RETURN_PATH_MISMATCH", "low", 4, "Envelope sender differs from From domain",
              f"Return-Path {defang(rp_dom)} vs From {defang(from_dom)} (common for ESPs; context only)")

    mid = re.search(r"@([^>\s]+)>?$", pe.message_id or "")
    if mid and from_dom and not same_org(mid.group(1), from_dom):
        F.add("MESSAGE_ID_MISMATCH", "info", 2, "Message-ID domain differs from From domain",
              f"{defang(mid.group(1).lower())} vs {defang(from_dom)}")

    # ------------------------------------------------------------ links
    for ind in iocs.of_type("url"):
        if "internal" in ind.tags or "benign-infrastructure" in ind.tags:
            continue
        m, d = ind.meta, ind.defanged
        if m.get("is_ip"):
            F.add("URL_IP_LITERAL", "medium", 15, "Link points to a raw IP address", d)
        if m.get("userinfo"):
            F.add("URL_USERINFO", "high", 20, "Link uses user@host obfuscation", d)
        if m.get("punycode"):
            F.add("URL_PUNYCODE", "medium", 15, "Link uses an internationalized (punycode) domain",
                  f"{d} renders as {m.get('unicode_host')}")
        if m.get("port") and m["port"] not in (80, 443):
            F.add("URL_NONSTANDARD_PORT", "low", 5, "Link uses a non-standard port", d)
        if domain_in(m.get("host"), an["free_hosting_suffixes"]):
            F.add("URL_FREE_HOSTING", "medium", 10, "Link hosted on a free hosting / IPFS platform", d)
        if domain_in(m.get("host"), an["url_shorteners"]):
            F.add("URL_SHORTENER", "low", 8, "Link uses a URL shortener (destination hidden)", d)
        if "recipient-identifier" in ind.tags:
            F.add("URL_RECIPIENT_TOKEN", "low", 5, "Link is personalised with the recipient's address",
                  f"{d} (tracks/pre-fills the victim)")
        if not m.get("is_ip") and not domain_in(m.get("host"), internal):
            hit = lookalike(m.get("host", ""), protected)
            if hit:
                sev, w = ("medium", 20) if hit["kind"] == "embedded-brand" else ("high", 30)
                F.add("LOOKALIKE_LINK_DOMAIN", sev, w, "Link domain imitates a protected domain",
                      f"{defang(m['host'])}: {hit['kind']} of {hit['target']}")

    for source, snippet in iocs.script_links:
        F.add("URL_SCRIPT_SCHEME", "high", 20, "Link uses javascript:/data: scheme", f"{source}: {snippet[:40]}")

    # ------------------------------------------------------------ HTML content (bodies + attachments)
    scans = [("body", s) for s in pe.html_scans] + [(f"attachment {a.filename}", a.html)
                                                    for a in pe.attachments if a.html]
    for where, scan in scans:
        for href, text in scan.anchors:
            shown = _anchor_shown_host(text)
            actual = _href_host(href)
            if shown and actual and not same_org(shown, actual):
                F.add("LINK_TEXT_MISMATCH", "high", 25, "Link text shows a different domain than its target",
                      f"text '{defang(shown)}' -> {defang(actual)}")
        for form in scan.forms:
            action = form.get("action") or "(same page)"
            if form.get("password"):
                F.add("CREDENTIAL_FORM", "high", 25, "HTML form collects a password",
                      f"{where}: posts to {defang(action, 'url')}")
            else:
                F.add("HTML_FORM", "medium", 10, "HTML form embedded", f"{where}: posts to {defang(action, 'url')}")
        if scan.password_inputs and not scan.forms:
            F.add("CREDENTIAL_FORM", "high", 25, "HTML form collects a password", f"{where}: password field")
        recips = set(pe.recipient_addresses())
        if any(v.strip().lower() in recips for v in scan.prefilled_values):
            F.add("PREFILLED_RECIPIENT", "medium", 10, "Form is pre-filled with the recipient's address",
                  f"{where}: targeted kit (personalised per victim)")
        if where != "body" and scan.js_traits:
            F.add("HTML_SMUGGLING_TRAITS", "medium", 20, "HTML attachment contains loader/exfil script traits",
                  f"{where}: {', '.join(scan.js_traits[:5])}")
        elif where == "body" and scan.scripts:
            F.add("SCRIPT_IN_BODY", "medium", 10, "Script in email body (kit/template artefact)",
                  f"{scan.scripts} <script> block(s)")
        if where != "body" and scan.meta_refresh:
            F.add("HTML_REDIRECT", "medium", 15, "HTML attachment auto-redirects",
                  f"{where}: meta refresh -> {defang(scan.meta_refresh[0], 'url')}")

    for scan in pe.html_scans:
        plain_len = max((len(b.strip()) for b in pe.text_bodies), default=0)
        if scan.images and len(scan.visible_text) < 80 and plain_len < 80:
            F.add("IMAGE_ONLY_BODY", "medium", 10, "Body is mostly images (check for QR-code phishing)",
                  f"{scan.images} image(s), {len(scan.visible_text)} chars of text - decode any QR code manually")

    # ------------------------------------------------------------ attachments
    for a in pe.attachments:
        exts, ext, name = a.extensions, a.ext, a.filename
        if a.detected_type == "message/rfc822":
            a.flags.append("embedded email")
            continue
        if "‮" in name:
            F.add("ATTACHMENT_RTLO", "high", 30, "Attachment name uses right-to-left override", repr(name))
            a.flags.append("RTLO in name")
        if ext in EXEC_EXTS or a.detected_type in ("pe-executable", "elf-executable", "lnk"):
            F.add("ATTACHMENT_EXECUTABLE", "high", 35, "Executable/script attachment",
                  f"{name} ({a.detected_type})")
            a.flags.append("executable")
        elif ext in DISK_IMAGE_EXTS or a.detected_type == "iso9660":
            F.add("ATTACHMENT_DISK_IMAGE", "high", 30, "Disk-image attachment (MOTW bypass)", name)
            a.flags.append("disk image")
        elif ext in ONENOTE_EXTS:
            F.add("ATTACHMENT_ONENOTE", "high", 25, "OneNote attachment (common loader)", name)
            a.flags.append("OneNote")
        elif ext in HTML_EXTS or a.detected_type in ("html", "svg"):
            F.add("ATTACHMENT_HTML", "medium", 20, "HTML/SVG attachment (credential page or smuggling)", name)
            a.flags.append("HTML/SVG")
        if ext in MACRO_EXTS or a.has_macros:
            F.add("ATTACHMENT_MACRO", "high", 25, "Macro-enabled document",
                  f"{name}{' (VBA project present)' if a.has_macros else ''}")
            a.flags.append("macros")
        if len(exts) >= 2 and exts[-2] in DECOY_EXTS and (
                ext in EXEC_EXTS | DISK_IMAGE_EXTS | HTML_EXTS | ONENOTE_EXTS | MACRO_EXTS):
            F.add("ATTACHMENT_DOUBLE_EXTENSION", "high", 25, "Attachment uses a decoy double extension", name)
            a.flags.append("double extension")
        exp = EXPECTED_TYPES.get(ext)
        if exp and a.detected_type not in exp and a.detected_type not in ("unknown", "empty"):
            F.add("ATTACHMENT_TYPE_MISMATCH", "medium", 15, "Attachment content does not match its extension",
                  f"{name}: .{ext} but content is {a.detected_type}")
            a.flags.append(f"content is {a.detected_type}")
        if a.archive_entries or ext in ARCHIVE_EXTS:
            if a.archive_encrypted:
                F.add("ATTACHMENT_ENCRYPTED_ARCHIVE", "medium", 20, "Password-protected archive (evades scanning)", name)
                a.flags.append("encrypted archive")
            risky = [e for e in a.archive_entries
                     if e.lower().rsplit(".", 1)[-1] in EXEC_EXTS | DISK_IMAGE_EXTS | HTML_EXTS | ONENOTE_EXTS]
            if risky:
                F.add("ATTACHMENT_ARCHIVE_RISKY", "high", 30, "Archive contains executable/script/HTML content",
                      f"{name}: {', '.join(risky[:4])}")
                a.flags.append("risky archive content")

    # ------------------------------------------------------------ lure language
    texts = [pe.subject] + pe.text_bodies + [s.visible_text for s in pe.html_scans] + \
            [a.html.visible_text for a in pe.attachments if a.html]
    blob = " ".join(texts).lower()
    hits = [t for t in an["urgency_terms"] + an["credential_terms"] if t in blob]
    if len(hits) >= 3:
        F.add("LURE_LANGUAGE", "low", 10, "Urgency / credential-lure language", ", ".join(hits[:6]))
    elif hits:
        F.add("LURE_LANGUAGE", "low", 5, "Urgency / credential-lure language", ", ".join(hits))

    # ------------------------------------------------------------ transport anomalies
    for h in pe.hops:
        if h.delay_s is not None and h.delay_s < -300:
            F.add("RECEIVED_TIME_ANOMALY", "low", 3, "Received timestamps go backwards",
                  f"hop by {h.by_host}: {int(h.delay_s)} s")
    stamps = [h.timestamp for h in pe.hops if h.timestamp]
    if pe.date is None:
        F.add("DATE_ANOMALY", "low", 3, "Missing or unparseable Date header", pe.date_raw or "(none)")
    elif stamps and (pe.date - min(stamps) > timedelta(hours=1) or max(stamps) - pe.date > timedelta(days=3)):
        F.add("DATE_ANOMALY", "low", 3, "Date header inconsistent with delivery path",
              f"Date {pe.date.isoformat()} vs hops {min(stamps).isoformat()}..{max(stamps).isoformat()}")

    # ------------------------------------------------------------ reputation (after enrichment)
    for ind in iocs.all():
        for r in ind.reputation:
            if r.status == "malicious":
                F.add("REPUTATION_MALICIOUS", "high", 50, "Indicator flagged malicious by an approved source",
                      f"{ind.defanged} - {r.source}: {r.summary}")
            elif r.status == "suspicious":
                F.add("REPUTATION_SUSPICIOUS", "medium", 15, "Indicator flagged suspicious by an approved source",
                      f"{ind.defanged} - {r.source}: {r.summary}")
            created = r.data.get("domain_age_days") if r.data else None
            if created is not None and created < 30:
                F.add("YOUNG_DOMAIN", "medium", 15, "Recently registered domain",
                      f"{ind.defanged}: ~{created} days old ({r.source})")
    return F.list()
