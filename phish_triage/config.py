"""Configuration loading (TOML, stdlib only) with safe defaults."""
from __future__ import annotations

import copy
import fnmatch
import tomllib
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "organization": {
        "name": "",
        "internal_domains": [],
        "protected_domains": [],
        "protected_display_names": [],
        # authserv-ids whose Authentication-Results you trust. Use ["topmost"] to trust the
        # topmost header regardless of id (e.g. Microsoft 365, which omits the authserv-id).
        "trusted_authserv_ids": [],
        # Your own MTAs / gateways; used to find the trust-boundary (real origin) IP.
        "trusted_mta_hosts": [],
    },
    "analysis": {
        "max_email_bytes": 25 * 1024 * 1024,
        "max_text_attachment_bytes": 2 * 1024 * 1024,
        "max_mime_depth": 15,
        "unwrap_reported_messages": True,
        "redact_recipients": True,
        "benign_domains": [
            "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
            "purl.org", "xmlns.com", "ogp.me", "schema.org",
        ],
        "freemail_domains": [
            "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
            "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com", "gmx.com",
            "gmx.net", "proton.me", "protonmail.com", "zoho.com", "yandex.com", "yandex.ru",
            "mail.ru", "rediffmail.com", "qq.com", "163.com",
        ],
        "url_shorteners": [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
            "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in", "qrco.de",
        ],
        # Free hosting / dev platforms and IPFS gateways commonly abused to host phishing pages.
        "free_hosting_suffixes": [
            "github.io", "gitlab.io", "web.app", "firebaseapp.com", "firebasestorage.googleapis.com",
            "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "herokuapp.com",
            "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "appspot.com",
            "glitch.me", "onrender.com", "ngrok.io", "ngrok-free.app", "s3.amazonaws.com",
            "storage.googleapis.com", "wixsite.com", "weebly.com", "square.site", "webflow.io",
            "ipfs.io", "dweb.link", "cf-ipfs.com", "ipfs.w3s.link", "nftstorage.link",
        ],
        "urgency_terms": [
            "urgent", "immediately", "within 24 hours", "within 48 hours", "expires today",
            "expire today", "final notice", "final warning", "action required", "act now",
            "suspended", "suspension", "will be closed", "will be deleted", "will be disabled",
            "overdue", "asap", "past due",
        ],
        "credential_terms": [
            "verify your account", "confirm your identity", "password expires",
            "password will expire", "reset your password", "keep my current password",
            "keep my password", "sign in to view", "login to view", "log in to view",
            "sign in with your email", "validate your", "mailbox quota", "mailbox is full",
            "unusual sign-in", "update your payment", "reactivate", "re-activate",
            "shared a document with you", "new voicemail", "secure message",
        ],
    },
    "reputation": {
        "max_lookups_per_run": 60,
        "timeout_seconds": 15,
        "cache_path": "../.triage-cache/reputation.json",
        "cache_ttl_hours": 24,
        # full | strip_fragment | strip_query. URLs carrying a recipient identifier are
        # always sent with query and fragment stripped, whatever this says.
        "url_outbound_policy": "strip_fragment",
    },
    "sources": {
        "local_intel": {"enabled": True, "path": "local_intel.csv"},
    },
}

_LOWER_LISTS = {
    ("organization", "internal_domains"),
    ("organization", "protected_domains"),
    ("organization", "trusted_authserv_ids"),
    ("organization", "trusted_mta_hosts"),
    ("analysis", "benign_domains"),
    ("analysis", "freemail_domains"),
    ("analysis", "url_shorteners"),
    ("analysis", "free_hosting_suffixes"),
    ("analysis", "urgency_terms"),
    ("analysis", "credential_terms"),
}


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def domain_in(host: str | None, domains) -> bool:
    """host equals, or is a subdomain of, any domain in `domains`."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def host_matches(host: str | None, patterns) -> bool:
    """fnmatch-style match (e.g. '*.example.com'); a bare domain also matches its subdomains."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    for p in patterns:
        if fnmatch.fnmatchcase(h, p) or (not any(c in p for c in "*?[") and domain_in(h, [p])):
            return True
    return False


class Config:
    def __init__(self, data: dict, base_dir: Path, source: str | None):
        self.data = data
        self.base_dir = base_dir
        self.source = source

    @property
    def org(self) -> dict:
        return self.data["organization"]

    @property
    def analysis(self) -> dict:
        return self.data["analysis"]

    @property
    def rep(self) -> dict:
        return self.data["reputation"]

    @property
    def sources(self) -> dict:
        return self.data["sources"]

    def resolve(self, p: str | Path) -> Path:
        p = Path(p).expanduser()
        return p if p.is_absolute() else (self.base_dir / p).resolve()


def load_config(path: str | Path | None = None) -> Config:
    data = copy.deepcopy(DEFAULTS)
    base_dir = Path.cwd()
    source = None
    if path:
        p = Path(path)
        with p.open("rb") as fh:
            _deep_merge(data, tomllib.load(fh))
        base_dir = p.resolve().parent
        source = str(p)
    for section, key in _LOWER_LISTS:
        data[section][key] = [str(x).lower().strip() for x in data[section].get(key, []) if str(x).strip()]
    return Config(data, base_dir, source)
