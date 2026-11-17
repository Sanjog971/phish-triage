"""Domain helpers: registrable domain, IDN handling and lookalike detection (offline)."""
from __future__ import annotations

import re
import unicodedata

from .safety import parse_ip

# Fallback when `tldextract` is not installed. Covers the common multi-label suffixes;
# install tldextract (it uses its bundled offline snapshot here) for full PSL accuracy.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "firm.in", "gen.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "com.my",
    "com.mx", "com.ar", "com.tr", "com.tw", "com.ph", "com.pk", "com.ng", "com.sa", "com.eg",
    "co.za", "co.nz", "co.kr", "co.id", "co.il", "co.th", "co.ke",
    # PSL "private" suffixes heavily used for phishing hosting: each subdomain is a separate owner
    "github.io", "gitlab.io", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "r2.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "blob.core.windows.net",
    "web.core.windows.net", "appspot.com", "glitch.me", "onrender.com", "ngrok.io", "ngrok-free.app",
    "s3.amazonaws.com", "cloudfront.net", "wixsite.com", "weebly.com", "blogspot.com",
}

try:  # optional, offline-only use of the bundled Public Suffix List snapshot
    import tldextract  # type: ignore

    _TLD = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:  # pragma: no cover - optional dependency
    _TLD = None


def registrable_domain(host: str | None) -> str:
    h = (host or "").lower().strip().rstrip(".")
    if not h or parse_ip(h):
        return h
    if _TLD is not None:
        try:
            r = _TLD(h)
            if r.domain and r.suffix:
                return f"{r.domain}.{r.suffix}"
        except Exception:
            pass
    labels = h.split(".")
    for k in (4, 3, 2):  # longest known multi-label suffix wins
        if len(labels) > k and ".".join(labels[-k:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-(k + 1):])
    return ".".join(labels[-2:])


def same_org(a: str | None, b: str | None) -> bool:
    return bool(a and b) and registrable_domain(a) == registrable_domain(b)


def to_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


# Characters commonly substituted in lookalike domains -> their Latin "skeleton".
_CONFUSABLES = {
    "0": "o", "1": "l", "i": "l", "|": "l", "ı": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "$": "s", "@": "a",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l",
    "ј": "j", "ԁ": "d", "ѕ": "s", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t",
    "в": "b", "н": "h", "г": "r", "ԛ": "q", "ԝ": "w",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "l", "κ": "k", "ε": "e", "β": "b",
    "ɡ": "g", "ɑ": "a",
}


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower()
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s)
    for a, b in (("rn", "m"), ("vv", "w")):
        s = s.replace(a, b)
    return s


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(host: str, protected: list[str], min_len: int = 4) -> dict | None:
    """Return {'kind', 'target', 'detail'} if `host` imitates a protected domain."""
    host = (host or "").lower().rstrip(".")
    if not host or parse_ip(host) or not protected:
        return None
    if any(host == p or host.endswith("." + p) for p in protected):
        return None
    reg = registrable_domain(host)
    u_reg = to_unicode(reg)
    reg_label = u_reg.split(".")[0]
    sk_label = skeleton(reg_label)
    sub = host[: -len(reg)].rstrip(".") if host != reg else ""
    no_suffix = to_unicode((sub + "." if sub else "") + reg.split(".")[0])
    sk_tokens = [t for t in re.split(r"[.\-_]+", skeleton(no_suffix)) if t]
    raw_tokens = [t for t in re.split(r"[.\-_]+", no_suffix.lower()) if t]

    for p in protected:
        p_label = registrable_domain(p).split(".")[0]
        if len(p_label) < min_len:
            continue
        p_sk = skeleton(p_label)
        if sk_label == p_sk:
            if reg_label != p_label:
                return {"kind": "homoglyph", "target": p, "detail": f"{to_unicode(host)} imitates {p}"}
            return {"kind": "tld-swap", "target": p, "detail": f"same name as {p} on a different suffix"}
        if len(p_sk) >= 5:
            d = levenshtein(sk_label, p_sk)
            if 0 < d <= (1 if len(p_sk) <= 7 else 2):
                return {"kind": "typosquat", "target": p, "detail": f"edit distance {d} from {p}"}
        if p_sk in sk_tokens or (len(p_sk) >= 6 and any(p_sk in t for t in sk_tokens)):
            if p_label in raw_tokens or any(p_label in t for t in raw_tokens):
                return {"kind": "embedded-brand", "target": p, "detail": f"'{p_label}' used inside an unrelated domain"}
            return {"kind": "embedded-homoglyph", "target": p,
                    "detail": f"'{p_label}' spelled with look-alike characters inside an unrelated domain"}
    return None
