"""URL extraction, normalization and unwrapping of link-protection rewrites (offline)."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

from .safety import parse_ip

URL_RX = re.compile(r"""(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>"'`{}|\\^]+""", re.I)


def _trim(u: str) -> str:
    while u and u[-1] in ".,;:!?'\">":
        u = u[:-1]
    for o, c in (("(", ")"), ("[", "]"), ("{", "}")):
        while u.endswith(c) and u.count(c) > u.count(o):
            u = u[:-1]
    return u


def find_urls(text: str) -> list[str]:
    out = []
    for m in URL_RX.finditer(text or ""):
        u = _trim(m.group(0))
        if len(u) > 10:
            out.append(u)
    return out


@dataclass
class UrlParts:
    scheme: str
    host: str
    port: int | None
    has_userinfo: bool
    is_ip: bool
    punycode: bool
    unicode_host: str | None


def normalize_url(raw: str) -> str | None:
    """Lower-case scheme/host, IDNA-encode the host; keep path/query/fragment untouched."""
    u = (raw or "").strip().strip("<>\"'")
    if not u:
        return None
    if u.lower().startswith("www."):
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = p.hostname
        port = p.port
    except ValueError:
        return None
    scheme = p.scheme.lower()
    if scheme not in ("http", "https", "ftp") or not host:
        return None
    host = host.rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    if "@" in p.netloc:
        netloc = p.netloc.rsplit("@", 1)[0] + "@" + netloc
    return urlunsplit((scheme, netloc, p.path, p.query, p.fragment))


def url_parts(url: str) -> UrlParts:
    p = urlsplit(url)
    host = p.hostname or ""
    try:
        port = p.port
    except ValueError:
        port = None
    puny = any(lbl.startswith("xn--") for lbl in host.split("."))
    uni = None
    if puny:
        try:
            uni = host.encode("ascii").decode("idna")
        except UnicodeError:
            uni = None
    return UrlParts(p.scheme, host, port, "@" in p.netloc, parse_ip(host) is not None, puny, uni)


def strip_url(url: str, query: bool = True, fragment: bool = True) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "" if query else p.query, "" if fragment else p.fragment))


# ------------------------------------------------------------------ link-protection unwrapping

_PP_V3_RUNS = {c: i + 2 for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}


def _proofpoint_v2(u: str) -> str:
    return unquote(u.replace("-", "%").replace("_", "/"))


def _proofpoint_v3(url: str) -> str | None:
    m = re.search(r"v3/__(?P<url>.+?)__;(?P<enc>.*?)!", url)
    if not m:
        return None
    embedded, enc = m.group("url"), m.group("enc")
    try:
        chars = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8")
    except Exception:
        chars = ""
    out, ci, i = [], 0, 0
    while i < len(embedded):
        if embedded.startswith("**", i) and i + 2 < len(embedded) and embedded[i + 2] in _PP_V3_RUNS:
            n = _PP_V3_RUNS[embedded[i + 2]]
            out.append(chars[ci:ci + n])
            ci += n
            i += 3
        elif embedded[i] == "*" and ci < len(chars):
            out.append(chars[ci])
            ci += 1
            i += 1
        else:
            out.append(embedded[i])
            i += 1
    return "".join(out)


def _unwrap_once(url: str) -> tuple[str | None, str | None]:
    try:
        p = urlsplit(url)
    except ValueError:
        return None, None
    host = (p.hostname or "").lower()
    qs = parse_qs(p.query)
    if host.endswith("safelinks.protection.outlook.com") and qs.get("url"):
        return qs["url"][0], "microsoft-safelinks"
    if host == "urldefense.proofpoint.com" and p.path.startswith("/v2/url") and qs.get("u"):
        return _proofpoint_v2(qs["u"][0]), "proofpoint-v2"
    if host == "urldefense.com" and p.path.startswith("/v3/"):
        r = _proofpoint_v3(url)
        return (r, "proofpoint-v3") if r else (None, None)
    if host == "linkprotect.cudasvc.com" and qs.get("a"):
        return qs["a"][0], "barracuda-linkprotect"
    if host in ("www.google.com", "google.com") and p.path == "/url" and (qs.get("q") or qs.get("url")):
        return (qs.get("q") or qs.get("url"))[0], "google-redirect"
    return None, None


def unwrap_url(url: str, max_depth: int = 4) -> tuple[str, list[str]]:
    """Return (final_url, [wrapper names]) — purely string manipulation, no requests."""
    chain: list[str] = []
    cur = url
    for _ in range(max_depth):
        nxt, name = _unwrap_once(cur)
        if not nxt or nxt == cur or not re.match(r"(?i)^(?:https?|ftp)://", nxt):
            break
        chain.append(name)
        cur = nxt
    return cur, chain
