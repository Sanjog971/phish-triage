"""Indicator (IOC) extraction, de-duplication and lookup-eligibility classification."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

from .config import Config, domain_in
from .parse import ParsedEmail
from .safety import defang, is_internal_ip, is_reserved_domain, parse_ip, refang
from .urls import find_urls, normalize_url, unwrap_url, url_parts

EMAIL_RX = re.compile(r"(?<![\w.+-])([a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24})(?![\w-])", re.I)
TYPE_ORDER = {"url": 0, "domain": 1, "ip": 2, "sha256": 3, "email": 4}
STATUS_RANK = {"malicious": 0, "suspicious": 1, "no_detection": 2, "not_found": 3,
               "allowlisted": 4, "error": 5, "blocked": 6}


@dataclass
class Indicator:
    type: str
    value: str
    sources: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    lookup_eligible: bool = True
    skip_reason: str | None = None
    wrapped: list = field(default_factory=list)
    display: str | None = None          # redacted variant for reports (e.g. recipient token removed)
    meta: dict = field(default_factory=dict)
    reputation: list = field(default_factory=list)

    @property
    def defanged(self) -> str:
        return defang(self.display or self.value, self.type)

    def tag(self, t: str):
        if t not in self.tags:
            self.tags.append(t)

    @property
    def worst_status(self) -> str | None:
        st = [r.status for r in self.reputation]
        return min(st, key=lambda s: STATUS_RANK.get(s, 9)) if st else None

    @property
    def hidden(self) -> bool:
        """Internal / benign infrastructure: kept in JSON, hidden from the human report."""
        if "internal" in self.tags or "benign-infrastructure" in self.tags:
            return True
        return self.type == "domain" and "freemail" in self.tags


class IndicatorSet:
    def __init__(self):
        self._items: dict[tuple[str, str], Indicator] = {}
        self.script_links: list[tuple[str, str]] = []

    def add(self, type_: str, value: str, source: str) -> Indicator:
        key = (type_, value)
        ind = self._items.get(key)
        if ind is None:
            ind = self._items[key] = Indicator(type_, value)
        if source not in ind.sources:
            ind.sources.append(source)
        return ind

    def all(self) -> list[Indicator]:
        return sorted(self._items.values(), key=lambda i: TYPE_ORDER.get(i.type, 9))

    def of_type(self, t: str) -> list[Indicator]:
        return [i for i in self.all() if i.type == t]

    def get(self, t: str, v: str) -> Indicator | None:
        return self._items.get((t, v))

    def __len__(self):
        return len(self._items)


def _recipient_tokens(recipients: list[str]) -> tuple[set[str], set[str]]:
    """Plain/URL-encoded forms (case-insensitive) and base64 forms (case-sensitive)."""
    plain, b64 = set(), set()
    for r in recipients:
        plain.update({r.lower(), quote(r, safe="").lower(), quote(r).lower()})
        raw = r.encode()
        for enc in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            b64.update({enc, enc.rstrip("=")})
    return {t for t in plain if len(t) >= 6}, {t for t in b64 if len(t) >= 8}


def _find_token(url: str, plain: set[str], b64: set[str]) -> str | None:
    low = url.lower()
    for t in sorted(plain, key=len, reverse=True):
        idx = low.find(t)
        if idx >= 0:
            return url[idx: idx + len(t)]
    for t in sorted(b64, key=len, reverse=True):
        if t in url:
            return t
    return None


class _Extractor:
    def __init__(self, pe: ParsedEmail, cfg: Config):
        self.pe, self.cfg, self.S = pe, cfg, IndicatorSet()
        self.recipients = set(pe.recipient_addresses())
        self.plain_tokens, self.b64_tokens = _recipient_tokens(sorted(self.recipients))
        self.redact = cfg.analysis["redact_recipients"]

    def email(self, addr: str, source: str, add_domain: bool = True):
        addr = (addr or "").strip().strip("<>").lower()
        if "@" not in addr or addr in self.recipients:
            return
        if domain_in(addr.rpartition("@")[2], self.cfg.org["internal_domains"]) and source.startswith("body"):
            return  # colleagues mentioned in the body are not indicators
        self.S.add("email", addr, source)
        if add_domain:
            self.S.add("domain", addr.rpartition("@")[2], source)

    def url(self, raw: str, source: str):
        raw = (raw or "").strip()
        low = raw.lower()
        if low.startswith("mailto:"):
            self.email(unquote(raw[7:].split("?")[0]), source)
            return
        if low.startswith(("javascript:", "data:", "vbscript:")):
            self.S.script_links.append((source, raw[:80]))
            return
        n = normalize_url(raw)
        if not n:
            return
        final, chain = unwrap_url(n)
        final_n = normalize_url(final) if chain else n
        if not final_n:
            return
        ind = self.S.add("url", final_n, source)
        if chain:
            ind.tag("unwrapped:" + chain[0])
            if n not in ind.wrapped and len(ind.wrapped) < 3:
                ind.wrapped.append(n)
        parts = url_parts(final_n)
        ind.meta = {"host": parts.host, "port": parts.port, "is_ip": parts.is_ip,
                    "userinfo": parts.has_userinfo, "punycode": parts.punycode,
                    "unicode_host": parts.unicode_host, "scheme": parts.scheme}
        tok = _find_token(final_n, self.plain_tokens, self.b64_tokens)
        if tok:
            ind.tag("recipient-identifier")
            if self.redact:
                ind.display = final_n.replace(tok, "[recipient-id]")
        if parts.host:
            self.S.add("ip" if parts.is_ip else "domain", parts.host, "link host")

    def text(self, text: str, source: str, skip: tuple = ()):
        t = refang(text or "")
        for u in find_urls(t):
            if any(u in a for a in skip):
                continue  # URL-looking anchor text: the href is the real target (mismatch is a finding)
            self.url(u, source)
        for e in EMAIL_RX.findall(t):
            self.email(e, source)

    def run(self) -> IndicatorSet:
        pe = self.pe
        if pe.from_:
            self.email(pe.from_.addr, "From")
        if pe.sender:
            self.email(pe.sender.addr, "Sender")
        for a in pe.reply_to:
            self.email(a.addr, "Reply-To")
        if pe.return_path:
            self.email(pe.return_path, "Return-Path")
        if pe.origin_ip:
            self.S.add("ip", pe.origin_ip, "origin IP")
        if pe.earliest_claimed_ip and pe.earliest_claimed_ip != pe.origin_ip:
            self.S.add("ip", pe.earliest_claimed_ip, "earliest Received hop")
        if pe.x_originating_ip:
            self.S.add("ip", pe.x_originating_ip, "X-Originating-IP")

        for body in pe.text_bodies:
            self.text(body, "text body")
        for scan in pe.html_scans:
            for u, tag, attr in scan.links:
                self.url(u, f"HTML {tag}.{attr}")
            anchor_texts = tuple(refang(t) for _, t in scan.anchors if t)
            self.text(scan.visible_text + "\n" + scan.script_text, "HTML text", anchor_texts)
        for att in pe.attachments:
            self.S.add("sha256", att.sha256, f"attachment {att.filename}")
            if att.html:
                for u, tag, attr in att.html.links:
                    self.url(u, f"attachment {att.filename} ({tag}.{attr})")
                anchor_texts = tuple(refang(t) for _, t in att.html.anchors if t)
                self.text(att.html.visible_text + "\n" + att.html.script_text,
                          f"attachment {att.filename} (text)", anchor_texts)
            elif att.text:
                self.text(att.text, f"attachment {att.filename}")
        if pe.list_unsubscribe:
            for u in re.findall(r"<([^>]+)>", pe.list_unsubscribe):
                if u.lower().startswith("http"):
                    self.url(u, "List-Unsubscribe")
        classify(self.S, self.cfg)
        return self.S


def classify(S: IndicatorSet, cfg: Config):
    internal = cfg.org["internal_domains"]
    benign = cfg.analysis["benign_domains"]
    freemail = cfg.analysis["freemail_domains"]

    def host_reason(ind: Indicator, host: str) -> str | None:
        ip = parse_ip(host)
        if ip is not None:
            if is_internal_ip(ip):
                ind.tag("internal")
                return "private/internal address"
            if not ip.is_global:
                ind.tag("reserved")
                return "non-routable or documentation range (sanitized)"
            return None
        if domain_in(host, internal):
            ind.tag("internal")
            return "internal domain"
        if domain_in(host, benign):
            ind.tag("benign-infrastructure")
            return "benign infrastructure"
        if domain_in(host, freemail):
            ind.tag("freemail")
            return "free-mail provider (shared infrastructure)"
        if is_reserved_domain(host):
            ind.tag("reserved")
            return "reserved/sanitized name (RFC 2606/6761)"
        return None

    for ind in S.all():
        reason = None
        if ind.type == "email":
            reason = "email addresses are never sent externally"
            host_reason(ind, ind.value.rpartition("@")[2])
        elif ind.type in ("domain", "ip"):
            reason = host_reason(ind, ind.value)
        elif ind.type == "url":
            reason = host_reason(ind, ind.meta.get("host", ""))
        if reason:
            ind.lookup_eligible, ind.skip_reason = False, reason


def extract_indicators(pe: ParsedEmail, cfg: Config) -> IndicatorSet:
    return _Extractor(pe, cfg).run()
