"""Defang / refang helpers and safety predicates.

Nothing in this module touches the network or the filesystem.
"""
from __future__ import annotations

import ipaddress
import re

# RFC 2606 / RFC 6761 / RFC 8375 / ICANN-reserved names. Sanitized samples use these,
# and they must never be sent to external reputation services.
RESERVED_TLDS = {"test", "example", "invalid", "localhost", "local", "internal"}
RESERVED_SUFFIXES = {"example.com", "example.net", "example.org", "home.arpa"}

_INTERNAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def parse_ip(value: str | None):
    """Return an ip_address object or None. Accepts bracketed IPv6 and 'IPv6:' prefixes."""
    if not value:
        return None
    v = value.strip().strip("[]")
    if v.lower().startswith("ipv6:"):
        v = v[5:]
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


def is_internal_ip(value) -> bool:
    ip = parse_ip(value) if isinstance(value, str) else value
    if ip is None:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def is_routable_ip(value) -> bool:
    """True only for globally routable addresses (documentation ranges are excluded)."""
    ip = parse_ip(value) if isinstance(value, str) else value
    return bool(ip is not None and ip.is_global)


def is_reserved_domain(domain: str) -> bool:
    d = (domain or "").lower().rstrip(".")
    if not d:
        return True
    if d.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(d == s or d.endswith("." + s) for s in RESERVED_SUFFIXES)


# --------------------------------------------------------------------------- defang

def _dots(s: str) -> str:
    return s.replace(".", "[.]")


def defang_url(url: str) -> str:
    m = re.match(r"(?is)^([a-z][a-z0-9+.\-]*)://([^/?#]*)(.*)$", url)
    if not m:
        return _dots(url)
    scheme, netloc, rest = m.groups()
    scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
    netloc = netloc.replace("@", "[@]")
    return f"{scheme}://{_dots(netloc)}{rest}"


def defang(value: str, kind: str | None = None) -> str:
    """Make an indicator non-clickable for reports. kind: url|domain|ip|email|sha256."""
    if not value:
        return value
    if kind is None:
        if "://" in value:
            kind = "url"
        elif "@" in value:
            kind = "email"
        else:
            kind = "domain"
    if kind == "url":
        return defang_url(value)
    if kind == "email":
        local, _, dom = value.rpartition("@")
        return f"{local}[@]{_dots(dom)}" if local else _dots(value)
    if kind in ("domain", "ip", "host"):
        return _dots(value)
    return value


_REFANG_RULES = [
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", re.I), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*@\s*\)", re.I), "@"),
    (re.compile(r"\bh(?:xx|XX|Xx|xX)p(s?)://"), r"http\1://"),
    (re.compile(r"\bfxp://", re.I), "ftp://"),
]


def refang(text: str) -> str:
    """Undo common defanging so sanitized samples still yield indicators."""
    for rx, repl in _REFANG_RULES:
        text = rx.sub(repl, text)
    return text


def redact_address(addr: str) -> str:
    local, sep, dom = (addr or "").partition("@")
    if not sep:
        return "***"
    return f"{local[:1]}***@{dom}"
