"""Static, read-only parsing of RFC 5322 (.eml) messages.

Safety properties:
  * attachments are hashed and inspected in memory only - never written to disk or executed;
  * archives are listed (names/flags) but never extracted;
  * HTML is tokenized, never rendered; no DNS or network activity happens here.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from .config import Config, host_matches
from .htmlscan import HtmlScan, scan_html
from .safety import is_internal_ip, parse_ip


class InputRejected(Exception):
    """The input violates a safety limit (size, nesting) and was not analyzed."""


# ----------------------------------------------------------------------------- models

@dataclass
class Address:
    display_name: str
    addr: str

    @property
    def domain(self) -> str:
        return self.addr.rpartition("@")[2].lower() if "@" in self.addr else ""

    def __str__(self) -> str:
        return f'"{self.display_name}" <{self.addr}>' if self.display_name else f"<{self.addr}>"


@dataclass
class AuthResults:
    source: str = "none"              # authentication-results | received-spf | none
    authserv_id: str | None = None
    trusted: bool = False
    spf: str | None = None
    spf_domain: str | None = None
    dkim: list = field(default_factory=list)   # [(result, domain)]
    dmarc: str | None = None
    dmarc_from: str | None = None
    dmarc_policy: str | None = None
    compauth: str | None = None
    ignored: list = field(default_factory=list)  # untrusted headers: {authserv_id, spf, dkim, dmarc}
    note: str = ""

    @property
    def dkim_result(self) -> str | None:
        if not self.dkim:
            return None
        results = [r for r, _ in self.dkim]
        return "pass" if "pass" in results else results[0]


@dataclass
class Hop:
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    timestamp: datetime | None
    delay_s: float | None = None


@dataclass
class Attachment:
    filename: str
    declared_type: str
    detected_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    disposition: str
    archive_entries: list = field(default_factory=list)
    archive_encrypted: bool = False
    has_macros: bool = False
    html: HtmlScan | None = None
    text: str | None = None
    flags: list = field(default_factory=list)

    @property
    def extensions(self) -> list[str]:
        name = self.filename.lower().strip().rstrip(".")
        parts = [p.strip() for p in name.split(".")[1:]]
        return [p for p in parts if p]

    @property
    def ext(self) -> str:
        e = self.extensions
        return e[-1] if e else ""


@dataclass
class ParsedEmail:
    path: str
    file_sha256: str
    size: int
    unwrapped_from: dict | None
    subject: str
    from_: Address | None
    sender: Address | None
    reply_to: list
    return_path: str | None
    to: list
    cc: list
    extra_recipients: list
    date: datetime | None
    date_raw: str | None
    message_id: str | None
    x_originating_ip: str | None
    list_unsubscribe: str | None
    auth: AuthResults
    dkim_signatures: list
    hops: list                      # header order: newest first
    origin_ip: str | None
    origin_method: str
    earliest_claimed_ip: str | None
    text_bodies: list
    html_bodies: list
    html_scans: list
    attachments: list
    defects: list

    def recipient_addresses(self) -> list[str]:
        out = {a.addr.lower() for a in self.to + self.cc if a.addr}
        out.update(a.lower() for a in self.extra_recipients)
        if self.unwrapped_from and self.unwrapped_from.get("reporter"):
            out.add(self.unwrapped_from["reporter"].lower())
        return sorted(x for x in out if "@" in x)


# ---------------------------------------------------------------------------- headers

def _raw_all(msg: EmailMessage, name: str) -> list[str]:
    n = name.lower()
    return [" ".join(str(v).split()) for k, v in msg.raw_items() if k.lower() == n]


def _h(msg: EmailMessage, name: str) -> str | None:
    try:
        v = msg.get(name)
        if v is not None:
            return " ".join(str(v).split())
    except Exception:
        pass
    vals = _raw_all(msg, name)
    return vals[0] if vals else None


def _addresses(msg: EmailMessage, name: str) -> list[Address]:
    try:
        h = msg.get(name)
        if h is None:
            return []
        addrs = getattr(h, "addresses", None)
        if addrs:
            out = []
            for a in addrs:
                spec = (a.addr_spec or "").strip("<>").lower()
                if spec or a.display_name:
                    out.append(Address(a.display_name or "", spec))
            return out
    except Exception:
        pass
    raw = ", ".join(_raw_all(msg, name))
    return [Address(n, a.lower()) for n, a in getaddresses([raw]) if a or n]


_COMMENT = re.compile(r"\([^()]*\)")


def _strip_comments(s: str) -> str:
    prev = None
    while prev != s:
        prev, s = s, _COMMENT.sub(" ", s)
    return s


_METHOD = re.compile(r"^\s*([a-z][a-z0-9_-]*)\s*=\s*([a-z0-9_-]+)", re.I)
_PROP = re.compile(r"\b([a-z][a-z0-9_-]*\.[a-z0-9_.-]+|action|reason)\s*=\s*(\"[^\"]*\"|[^\s;]+)", re.I)


def _parse_ar_value(raw: str) -> dict:
    policy_m = re.search(r"dmarc\s*=\s*\w+\s*\(([^)]*)\)", raw, re.I)
    s = _strip_comments(raw)
    clauses = [c.strip() for c in s.split(";") if c.strip()]
    res = {"authserv_id": None, "spf": None, "spf_domain": None, "dkim": [], "dmarc": None,
           "dmarc_from": None, "dmarc_policy": None, "compauth": None}
    if clauses and "=" not in clauses[0].split()[0]:
        res["authserv_id"] = clauses[0].split()[0].lower()
        clauses = clauses[1:]
    for c in clauses:
        m = _METHOD.match(c)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        props = {k.lower(): v.strip('"') for k, v in _PROP.findall(c[m.end():])}
        if method == "spf" and res["spf"] is None:
            res["spf"] = result
            dom = props.get("smtp.mailfrom") or props.get("smtp.helo")
            res["spf_domain"] = dom.rpartition("@")[2].lower() if dom else None
        elif method == "dkim":
            d = props.get("header.d") or props.get("header.i")
            d = d.rpartition("@")[2].lower() if d and d.lower() != "none" else None
            res["dkim"].append((result, d))
        elif method == "dmarc" and res["dmarc"] is None:
            res["dmarc"] = result
            res["dmarc_from"] = (props.get("header.from") or "").lower() or None
            pol = props.get("action")
            if not pol and policy_m:
                pm = re.search(r"\b(?:dis|p)=([a-z]+)", policy_m.group(1), re.I)
                pol = pm.group(1) if pm else None
            res["dmarc_policy"] = pol.lower() if pol else None
        elif method == "compauth":
            res["compauth"] = result
    return res


def parse_auth_results(values: list[str], received_spf: list[str], trusted: list[str]) -> AuthResults:
    """Pick the Authentication-Results header written by *your* MTA; ignore the rest."""
    parsed = [_parse_ar_value(v) for v in values]
    chosen, ignored, note = None, [], ""
    trust_topmost = "topmost" in trusted
    patterns = [t for t in trusted if t != "topmost"]
    for i, p in enumerate(parsed):
        if trust_topmost and i == 0:
            chosen, is_trusted = p, True
            note = "topmost Authentication-Results trusted by configuration"
            continue
        if patterns and p["authserv_id"] and host_matches(p["authserv_id"], patterns) and chosen is None:
            chosen, is_trusted = p, True
            continue
        if chosen is None and not trusted:
            chosen, is_trusted = p, False
            note = "authserv-id not verified (set organization.trusted_authserv_ids)"
            continue
        ignored.append({"authserv_id": p["authserv_id"], "spf": p["spf"],
                        "dkim": p["dkim"][0][0] if p["dkim"] else None, "dmarc": p["dmarc"]})
    if chosen is None:
        ar = AuthResults(ignored=ignored)
        if received_spf:
            m = re.match(r"\s*([a-z]+)", received_spf[0], re.I)
            if m:
                ar.source, ar.spf = "received-spf", m.group(1).lower()
                ar.note = "SPF from Received-SPF header only (unverified)"
        if ignored and not ar.note:
            ar.note = "no Authentication-Results header from a trusted authserv-id"
        return ar
    return AuthResults(source="authentication-results", authserv_id=chosen["authserv_id"],
                       trusted=is_trusted, spf=chosen["spf"], spf_domain=chosen["spf_domain"],
                       dkim=chosen["dkim"], dmarc=chosen["dmarc"], dmarc_from=chosen["dmarc_from"],
                       dmarc_policy=chosen["dmarc_policy"], compauth=chosen["compauth"],
                       ignored=ignored, note=note)


_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_BARE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def parse_received(raw: str) -> Hop:
    s = " ".join(raw.split())
    body, date_part = (s.rsplit(";", 1) + [None])[:2] if ";" in s else (s, None)
    m_from = re.match(r"\s*from\s+(.*?)(?=\s+by\s+|$)", body, re.I)
    from_part = m_from.group(1) if m_from else ""
    m_by = re.search(r"\bby\s+([^\s;()]+)", body, re.I)
    m_with = re.search(r"\bwith\s+([^\s;()]+)", body, re.I)
    ips = []
    for rx in (_BRACKET_IP, _BARE_IPV4):
        for cand in rx.findall(from_part):
            if parse_ip(cand) and cand not in ips:
                ips.append(cand)
    from_ip = next((ip for ip in ips if not is_internal_ip(ip)), ips[0] if ips else None)
    ts = None
    if date_part:
        try:
            ts = parsedate_to_datetime(date_part.strip())
            if ts.tzinfo is None:
                ts = None
        except Exception:
            ts = None
    from_host = from_part.split()[0].lower() if from_part else None
    return Hop(from_host, from_ip, m_by.group(1).lower() if m_by else None,
               m_with.group(1) if m_with else None, ts)


def find_origin(hops: list[Hop], trusted_mtas: list[str]) -> tuple[str | None, str, str | None]:
    """Return (origin_ip, method, earliest_claimed_ip). `hops` is newest-first."""
    earliest = next((h.from_ip for h in reversed(hops) if h.from_ip and not is_internal_ip(h.from_ip)), None)
    if trusted_mtas:
        for h in hops:
            if not host_matches(h.by_host, trusted_mtas):
                break
            from_trusted = host_matches(h.from_host, trusted_mtas) or (h.from_ip and is_internal_ip(h.from_ip))
            if from_trusted:
                continue
            if h.from_ip:
                return h.from_ip, f"trust boundary (handed to {h.by_host})", earliest
            break
    if earliest:
        return earliest, "earliest external hop (unverified - lower hops can be forged)", earliest
    return None, "not determined", None


# -------------------------------------------------------------------------- MIME body

def _walk_leaves(part: EmailMessage, depth: int, max_depth: int):
    if depth > max_depth:
        raise InputRejected(f"MIME nesting deeper than max_mime_depth={max_depth}")
    if depth > 0 and part.get_content_type() == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        for sp in part.iter_parts():
            yield from _walk_leaves(sp, depth + 1, max_depth)
    else:
        yield part


def _part_text(part: EmailMessage) -> str:
    try:
        c = part.get_content()
        if isinstance(c, bytes):
            c = c.decode("utf-8", "replace")
        if isinstance(c, str):
            return c
    except Exception:
        pass
    payload = part.get_payload(decode=True) or b""
    try:
        return payload.decode(part.get_content_charset() or "utf-8", "replace")
    except LookupError:
        return payload.decode("utf-8", "replace")


def sniff(data: bytes) -> str:
    head = data[:16]
    if not data:
        return "empty"
    sigs = [
        (b"MZ", "pe-executable"), (b"\x7fELF", "elf-executable"), (b"%PDF", "pdf"),
        (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"), (b"Rar!\x1a\x07", "rar"),
        (b"7z\xbc\xaf'\x1c", "7z"), (b"\x1f\x8b", "gzip"), (b"{\\rtf", "rtf"),
        (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"MSCF", "cab"), (b"\x89PNG", "png"),
        (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
    ]
    for sig, name in sigs:
        if head.startswith(sig):
            return name
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso9660"
    sample = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if sample.startswith(b"<svg") or (sample.startswith(b"<?xml") and b"<svg" in sample):
        return "svg"
    if sample.startswith((b"<!doctype html", b"<html")) or any(
            t in sample[:1024] for t in (b"<html", b"<script", b"<form", b"<body", b"<iframe")):
        return "html"
    if sample.startswith(b"<?xml"):
        return "xml"
    printable = sum(1 for b in data[:2048] if 32 <= b < 127 or b in (9, 10, 13))
    if printable / max(1, min(len(data), 2048)) > 0.95:
        return "text"
    return "unknown"


_OLE_VBA_MARKERS = ("_VBA_PROJECT".encode("utf-16-le"), "Macros".encode("utf-16-le"), b"VBA\x00")


def _inspect_zip(data: bytes) -> tuple[list[str], bool, bool, str | None]:
    entries, encrypted, macros, kind = [], False, False, None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:  # names/flags only - nothing is read or extracted
            for i, info in enumerate(zf.infolist()):
                if i >= 500:
                    break
                entries.append(info.filename)
                if info.flag_bits & 0x1:
                    encrypted = True
                if info.filename.lower().endswith("vbaproject.bin"):
                    macros = True
    except Exception:
        return entries, encrypted, macros, None
    names = {e.lower() for e in entries}
    if "[content_types].xml" in names:
        kind = "ooxml"
    elif "meta-inf/manifest.mf" in names:
        kind = "jar"
    elif "mimetype" in names:
        kind = "odf"
    return entries, encrypted, macros, kind


TEXTUAL = {"html", "svg", "xml", "text"}
TEXT_EXTS = {"html", "htm", "shtml", "xhtml", "svg", "txt", "xml", "js", "vbs", "hta", "url", "csv", "eml", "mht", "mhtml"}


def _attachment(part: EmailMessage, ctype: str, disp: str, fname: str | None, cfg: Config) -> Attachment:
    if ctype == "message/rfc822":
        payload = b""
        try:
            inner = part.get_payload(0)
            payload = inner.as_bytes(policy=policy.default.clone(linesep="\r\n"))
        except Exception:
            pass
        detected = "message/rfc822"
        fname = fname or "embedded-message.eml"
    else:
        payload = part.get_payload(decode=True) or b""
        detected = sniff(payload)
    att = Attachment(
        filename=fname or f"unnamed.{ctype.split('/')[-1]}",
        declared_type=ctype, detected_type=detected, size=len(payload),
        md5=hashlib.md5(payload).hexdigest(), sha1=hashlib.sha1(payload).hexdigest(),
        sha256=hashlib.sha256(payload).hexdigest(), disposition=disp or "none",
    )
    if detected == "zip":
        entries, enc, macros, kind = _inspect_zip(payload)
        att.archive_entries, att.archive_encrypted, att.has_macros = entries, enc, macros
        if kind:
            att.detected_type = kind
    elif detected == "ole2":
        att.has_macros = any(m in payload for m in _OLE_VBA_MARKERS)
    if att.detected_type in TEXTUAL or (att.ext in TEXT_EXTS and detected not in ("pe-executable", "zip")):
        limit = cfg.analysis["max_text_attachment_bytes"]
        text = payload[:limit].decode(part.get_content_charset() or "utf-8", "replace") if payload else ""
        att.text = text
        if att.detected_type in ("html", "svg") or att.ext in ("html", "htm", "shtml", "xhtml", "svg", "hta"):
            att.html = scan_html(text)
    return att


def _find_embedded_message(msg: EmailMessage, cfg: Config) -> tuple[EmailMessage | None, int]:
    found, first = 0, None
    for p in _walk_leaves(msg, 0, cfg.analysis["max_mime_depth"]):
        inner = None
        if p.get_content_type() == "message/rfc822":
            try:
                inner = p.get_payload(0)
            except Exception:
                inner = None
        elif (p.get_filename() or "").lower().endswith(".eml"):
            data = p.get_payload(decode=True) or b""
            if data:
                inner = BytesParser(policy=policy.default).parsebytes(data)
        if inner is not None:
            found += 1
            first = first or inner
    return first, found


# ----------------------------------------------------------------------------- entry

def parse_file(path: str | Path, cfg: Config) -> ParsedEmail:
    p = Path(path)
    size = p.stat().st_size
    limit = cfg.analysis["max_email_bytes"]
    if size > limit:
        raise InputRejected(f"{p.name}: {size} bytes exceeds max_email_bytes={limit}")
    return parse_bytes(p.read_bytes(), cfg, name=p.name)


def parse_bytes(data: bytes, cfg: Config, name: str = "<bytes>") -> ParsedEmail:
    file_sha = hashlib.sha256(data).hexdigest()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    unwrapped = None
    if cfg.analysis["unwrap_reported_messages"]:
        inner, count = _find_embedded_message(msg, cfg)
        if inner is not None:
            rep = _addresses(msg, "From")
            unwrapped = {"reporter": rep[0].addr if rep else None, "subject": _h(msg, "Subject"),
                         "date": _h(msg, "Date"), "embedded_messages": count}
            msg = inner

    defects = [type(d).__name__ for d in getattr(msg, "defects", [])]
    froms = _addresses(msg, "From")
    senders = _addresses(msg, "Sender")
    rp = _h(msg, "Return-Path")
    rp = rp.strip().strip("<>").lower() if rp else None

    date_raw = _h(msg, "Date")
    date = None
    if date_raw:
        try:
            date = parsedate_to_datetime(date_raw)
            if date.tzinfo is None:
                date = None
        except Exception:
            date = None

    org = cfg.org
    auth = parse_auth_results(_raw_all(msg, "Authentication-Results"), _raw_all(msg, "Received-SPF"),
                              org["trusted_authserv_ids"])
    dkim_sigs = []
    for raw in _raw_all(msg, "DKIM-Signature"):
        d = re.search(r"\bd=([^;\s]+)", raw)
        s = re.search(r"\bs=([^;\s]+)", raw)
        dkim_sigs.append({"d": d.group(1).lower() if d else None, "s": s.group(1) if s else None})

    hops = [parse_received(r) for r in _raw_all(msg, "Received")]
    chron = [h for h in reversed(hops) if h.timestamp]
    for prev, cur in zip(chron, chron[1:]):
        cur.delay_s = (cur.timestamp - prev.timestamp).total_seconds()
    origin_ip, origin_method, earliest = find_origin(hops, org["trusted_mta_hosts"])

    xoip = _h(msg, "X-Originating-IP")
    if xoip:
        xoip = xoip.strip("[] ")
        xoip = xoip if parse_ip(xoip) else None

    extra = []
    for hn in ("Delivered-To", "X-Original-To"):
        for v in _raw_all(msg, hn):
            extra += [a.lower() for _, a in getaddresses([v]) if a]

    text_bodies, html_bodies, html_scans, attachments = [], [], [], []
    for part in _walk_leaves(msg, 0, cfg.analysis["max_mime_depth"]):
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        fname = part.get_filename()
        if ctype in ("text/plain", "text/html") and disp != "attachment" and not fname:
            text = _part_text(part)
            if ctype == "text/plain":
                text_bodies.append(text)
            else:
                html_bodies.append(text)
                html_scans.append(scan_html(text))
            continue
        attachments.append(_attachment(part, ctype, disp, fname, cfg))

    return ParsedEmail(
        path=name, file_sha256=file_sha, size=len(data), unwrapped_from=unwrapped,
        subject=_h(msg, "Subject") or "", from_=froms[0] if froms else None,
        sender=senders[0] if senders else None, reply_to=_addresses(msg, "Reply-To"),
        return_path=rp or None, to=_addresses(msg, "To"), cc=_addresses(msg, "Cc"),
        extra_recipients=sorted(set(extra)), date=date, date_raw=date_raw,
        # raw value: the stdlib parser truncates malformed IDs, which would break exact-match hunting
        message_id=(_raw_all(msg, "Message-ID") or [None])[0], x_originating_ip=xoip,
        list_unsubscribe=_h(msg, "List-Unsubscribe"), auth=auth, dkim_signatures=dkim_sigs,
        hops=hops, origin_ip=origin_ip, origin_method=origin_method, earliest_claimed_ip=earliest,
        text_bodies=text_bodies, html_bodies=html_bodies, html_scans=html_scans,
        attachments=attachments, defects=defects,
    )
