"""Reputation providers. All are lookup-only: no submission, scanning or upload endpoints
are declared, so the GuardedClient will refuse them even if code tried to call them."""
from __future__ import annotations

import base64
import csv
import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote

from .. import __version__
from ..config import domain_in
from .http import Endpoint, GuardedClient, HttpResponse, PolicyViolation


@dataclass
class RepResult:
    source: str
    ioc_type: str
    value: str
    status: str            # malicious|suspicious|no_detection|not_found|allowlisted|error|blocked
    summary: str
    link: str | None = None
    data: dict = field(default_factory=dict)
    cached: bool = False
    checked_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_problem(resp: HttpResponse) -> str | None:
    if resp.status in (401, 403):
        return f"HTTP {resp.status}: authentication failed (check API key)"
    if resp.status == 429:
        return "HTTP 429: rate limited / quota exhausted"
    if resp.status >= 400:
        return f"HTTP {resp.status}"
    return None


class Provider:
    name = "base"
    host = ""
    supports: frozenset = frozenset()
    endpoints: list = []
    requires_key = True
    default_key_env = ""

    def __init__(self, scfg: dict, rcfg: dict, audit: list, transport=None, sleep=time.sleep):
        self.cfg = scfg
        self.key_env = scfg.get("api_key_env", self.default_key_env)
        self.api_key = os.environ.get(self.key_env) if self.key_env else None
        self.share = set(scfg.get("share", sorted(self.supports))) & set(self.supports)
        self.rpm = float(scfg.get("requests_per_minute", 0) or 0)
        self._last = 0.0
        self._sleep = sleep
        self.http = GuardedClient(self.name, self.endpoints, audit, timeout=rcfg["timeout_seconds"],
                                  transport=transport)

    def ready(self) -> tuple[bool, str]:
        if self.requires_key and not self.api_key:
            return False, f"API key env var {self.key_env} not set"
        if not self.share:
            return False, "share list is empty"
        return True, "ready"

    def accepts(self, ioc_type: str) -> bool:
        return ioc_type in self.share

    def result(self, t, v, status, summary, link=None, data=None) -> RepResult:
        return RepResult(self.name, t, v, status, summary, link, data or {}, False, _now())

    def _throttle(self):
        if self.rpm > 0:
            wait = 60.0 / self.rpm - (time.monotonic() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = time.monotonic()

    def lookup(self, ioc_type: str, value: str) -> RepResult:
        self._throttle()
        try:
            return self._lookup(ioc_type, value)
        except PolicyViolation as e:
            return self.result(ioc_type, value, "blocked", str(e))
        except Exception as e:  # network/parse errors never abort the triage
            msg = f"{type(e).__name__}: {e}"
            if self.api_key:
                msg = msg.replace(self.api_key, "***")
            return self.result(ioc_type, value, "error", msg[:200])

    def _lookup(self, ioc_type: str, value: str) -> RepResult:  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------- VirusTotal

class VirusTotal(Provider):
    name = "virustotal"
    host = "www.virustotal.com"
    supports = frozenset({"url", "domain", "ip", "sha256"})
    endpoints = [Endpoint("GET", "www.virustotal.com", p) for p in
                 ("/api/v3/urls/", "/api/v3/domains/", "/api/v3/ip_addresses/", "/api/v3/files/")]
    default_key_env = "VT_API_KEY"

    def _lookup(self, t, v):
        gui = "https://www.virustotal.com/gui"
        if t == "url":
            path = "/api/v3/urls/" + base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
            link = f"{gui}/url/{hashlib.sha256(v.encode()).hexdigest()}"
        elif t == "domain":
            path, link = f"/api/v3/domains/{quote(v)}", f"{gui}/domain/{v}"
        elif t == "ip":
            path, link = f"/api/v3/ip_addresses/{v}", f"{gui}/ip-address/{v}"
        else:
            path, link = f"/api/v3/files/{v}", f"{gui}/file/{v}"
        resp = self.http.request("GET", f"https://{self.host}{path}", ioc=(t, v),
                                 headers={"x-apikey": self.api_key})
        if resp.status == 404:
            return self.result(t, v, "not_found", "not in VirusTotal dataset")
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        data = resp.json().get("data") or {}
        attrs = data.get("attributes") or {}
        if t == "url" and data.get("id"):
            link = f"{gui}/url/{data['id']}"
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(x) for x in stats.values() if isinstance(x, (int, float)))
        thr = int(self.cfg.get("malicious_threshold", 3))
        status = ("malicious" if mal >= thr else "suspicious" if (mal > 0 or sus >= 2)
                  else "no_detection" if total else "not_found")
        summary = f"{mal}/{total} engines malicious" + (f", {sus} suspicious" if sus else "")
        extra = {"malicious": mal, "suspicious": sus, "engines": total}
        created = attrs.get("creation_date")
        if t == "domain" and isinstance(created, (int, float)) and created > 0:
            age = int((time.time() - created) // 86400)
            extra["domain_age_days"] = age
            summary += f"; registered ~{age} days ago"
        return self.result(t, v, status, summary, link, extra)


# --------------------------------------------------------------------------- AbuseIPDB

class AbuseIPDB(Provider):
    name = "abuseipdb"
    host = "api.abuseipdb.com"
    supports = frozenset({"ip"})
    endpoints = [Endpoint("GET", host, "/api/v2/check")]
    default_key_env = "ABUSEIPDB_API_KEY"

    def _lookup(self, t, v):
        resp = self.http.request("GET", f"https://{self.host}/api/v2/check", ioc=(t, v),
                                 headers={"Key": self.api_key},
                                 params={"ipAddress": v, "maxAgeInDays": int(self.cfg.get("max_age_days", 90))})
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        d = resp.json().get("data") or {}
        score, reports = int(d.get("abuseConfidenceScore") or 0), int(d.get("totalReports") or 0)
        status = ("malicious" if score >= int(self.cfg.get("malicious_score", 75))
                  else "suspicious" if score >= int(self.cfg.get("suspicious_score", 25))
                  else "no_detection")
        bits = [f"confidence {score}%", f"{reports} reports"]
        bits += [x for x in (d.get("usageType"), d.get("isp"), d.get("countryCode")) if x]
        if d.get("isTor"):
            bits.append("Tor exit")
        return self.result(t, v, status, ", ".join(bits), f"https://www.abuseipdb.com/check/{v}",
                           {"score": score, "reports": reports})


# --------------------------------------------------------------------------- abuse.ch

class URLhaus(Provider):
    name = "urlhaus"
    host = "urlhaus-api.abuse.ch"
    supports = frozenset({"url", "domain", "ip", "sha256"})
    endpoints = [Endpoint("POST", "urlhaus-api.abuse.ch", p) for p in ("/v1/url/", "/v1/host/", "/v1/payload/")]
    default_key_env = "ABUSECH_AUTH_KEY"

    def _lookup(self, t, v):
        if t == "url":
            path, form = "/v1/url/", {"url": v}
        elif t in ("domain", "ip"):
            path, form = "/v1/host/", {"host": v}
        else:
            path, form = "/v1/payload/", {"sha256_hash": v}
        resp = self.http.request("POST", f"https://{self.host}{path}", ioc=(t, v),
                                 headers={"Auth-Key": self.api_key}, form=form)
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        j = resp.json()
        qs = j.get("query_status")
        if qs in ("no_results", "not_found"):
            return self.result(t, v, "not_found", "not listed")
        if qs != "ok":
            return self.result(t, v, "error", f"query_status={qs}")
        if t == "url":
            tags = ", ".join(j.get("tags") or [])
            return self.result(t, v, "malicious",
                               f"listed: {j.get('threat') or 'malware'} ({j.get('url_status')})" + (f" [{tags}]" if tags else ""),
                               j.get("urlhaus_reference"), {"url_status": j.get("url_status")})
        if t in ("domain", "ip"):
            urls = j.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            try:
                count = int(j.get("url_count") or len(urls))
            except (TypeError, ValueError):
                count = len(urls)
            return self.result(t, v, "malicious" if online else "suspicious",
                               f"{count} malware URL(s) on host, {online} online", j.get("urlhaus_reference"),
                               {"url_count": count, "online": online})
        return self.result(t, v, "malicious",
                           f"payload known: {j.get('signature') or 'unclassified'} ({j.get('file_type') or '?'})",
                           f"https://urlhaus.abuse.ch/browse.php?search={v}")


class ThreatFox(Provider):
    name = "threatfox"
    host = "threatfox-api.abuse.ch"
    supports = frozenset({"url", "domain", "ip", "sha256"})
    endpoints = [Endpoint("POST", host, "/api/v1/")]
    default_key_env = "ABUSECH_AUTH_KEY"
    ALLOWED_QUERIES = {"search_ioc", "search_hash"}

    def _lookup(self, t, v):
        body = {"query": "search_hash", "hash": v} if t == "sha256" else {"query": "search_ioc", "search_term": v}
        assert body["query"] in self.ALLOWED_QUERIES
        resp = self.http.request("POST", f"https://{self.host}/api/v1/", ioc=(t, v),
                                 headers={"Auth-Key": self.api_key}, json_body=body)
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        j = resp.json()
        qs = j.get("query_status")
        if qs in ("no_result", "no_results", "hash_not_found"):
            return self.result(t, v, "not_found", "not listed")
        data = j.get("data") if isinstance(j.get("data"), list) else []
        if qs != "ok" or not data:
            return self.result(t, v, "error" if qs != "ok" else "not_found", f"query_status={qs}")
        top = max(data, key=lambda d: int(d.get("confidence_level") or 0))
        conf = int(top.get("confidence_level") or 0)
        return self.result(t, v, "malicious" if conf >= 50 else "suspicious",
                           f"{top.get('malware_printable') or top.get('malware') or '?'} "
                           f"({top.get('threat_type') or '?'}), confidence {conf}%, {len(data)} match(es)",
                           f"https://threatfox.abuse.ch/ioc/{top.get('id')}/" if top.get("id") else None,
                           {"confidence": conf, "matches": len(data)})


class MalwareBazaar(Provider):
    name = "malwarebazaar"
    host = "mb-api.abuse.ch"
    supports = frozenset({"sha256"})
    endpoints = [Endpoint("POST", host, "/api/v1/")]
    default_key_env = "ABUSECH_AUTH_KEY"

    def _lookup(self, t, v):
        resp = self.http.request("POST", f"https://{self.host}/api/v1/", ioc=(t, v),
                                 headers={"Auth-Key": self.api_key}, form={"query": "get_info", "hash": v})
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        j = resp.json()
        qs = j.get("query_status")
        if qs in ("hash_not_found", "no_results"):
            return self.result(t, v, "not_found", "not in MalwareBazaar")
        data = j.get("data") or []
        if qs != "ok" or not data:
            return self.result(t, v, "error", f"query_status={qs}")
        d = data[0]
        tags = ", ".join(d.get("tags") or [])
        return self.result(t, v, "malicious",
                           f"{d.get('signature') or 'unclassified'} ({d.get('file_type') or '?'})" + (f" [{tags}]" if tags else ""),
                           f"https://bazaar.abuse.ch/sample/{v}/", {"signature": d.get("signature")})


# --------------------------------------------------------------------------- Google Safe Browsing

class SafeBrowsing(Provider):
    """Lookup API v4. Google's terms restrict it to non-commercial use - approve accordingly."""
    name = "google_safe_browsing"
    host = "safebrowsing.googleapis.com"
    supports = frozenset({"url"})
    endpoints = [Endpoint("POST", host, "/v4/threatMatches:find")]
    default_key_env = "GSB_API_KEY"

    def _lookup(self, t, v):
        body = {"client": {"clientId": "phish-triage", "clientVersion": __version__},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                               "POTENTIALLY_HARMFUL_APPLICATION"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": v}]}}
        resp = self.http.request("POST", f"https://{self.host}/v4/threatMatches:find", ioc=(t, v),
                                 params={"key": self.api_key}, json_body=body)
        if (p := _http_problem(resp)):
            return self.result(t, v, "error", p)
        matches = resp.json().get("matches") or []
        link = f"https://transparencyreport.google.com/safe-browsing/search?url={quote(v, safe='')}"
        if matches:
            types = sorted({m.get("threatType", "?") for m in matches})
            return self.result(t, v, "malicious", "listed: " + ", ".join(types), link)
        return self.result(t, v, "no_detection", "not on Safe Browsing lists", link)


# --------------------------------------------------------------------------- local intel (offline)

class LocalIntel:
    """CSV of your own intel: type,value,verdict,note. Consulted offline; nothing leaves the host."""
    name = "local_intel"

    def __init__(self, path):
        self.path = path
        self.rows: dict[tuple[str, str], tuple[str, str]] = {}
        self.error = None
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                lines = [ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
            for row in csv.DictReader(lines):
                t = (row.get("type") or "").strip().lower()
                v = (row.get("value") or "").strip().lower()
                if t and v:
                    self.rows[(t, v)] = ((row.get("verdict") or "suspicious").strip().lower(),
                                         (row.get("note") or "").strip())
        except FileNotFoundError:
            self.error = f"{path} not found"

    def _res(self, ind, verdict, note, via=None):
        status = {"malicious": "malicious", "suspicious": "suspicious", "benign": "allowlisted"}.get(verdict, "suspicious")
        summary = note or verdict
        if via:
            summary += f" (via {via})"
        return RepResult(self.name, ind.type, ind.value, status, summary, None, {}, False, _now())

    def match(self, ind) -> RepResult | None:
        v = ind.value.lower()
        hit = self.rows.get((ind.type, v))
        if hit:
            return self._res(ind, *hit)
        host = None
        if ind.type == "domain":
            host = v
        elif ind.type == "url":
            host = (ind.meta.get("host") or "").lower()
        elif ind.type == "email":
            host = v.rpartition("@")[2]
        if host:
            for (t, val), (verdict, note) in self.rows.items():
                if t == "domain" and domain_in(host, [val]) and not (ind.type == "domain" and host == val):
                    return self._res(ind, verdict, note, f"domain entry {val}")
                if t == "ip" and ind.type == "url" and host == val:
                    return self._res(ind, verdict, note, f"ip entry {val}")
        return None


REGISTRY = {
    "virustotal": VirusTotal,
    "abuseipdb": AbuseIPDB,
    "urlhaus": URLhaus,
    "threatfox": ThreatFox,
    "malwarebazaar": MalwareBazaar,
    "google_safe_browsing": SafeBrowsing,
}
