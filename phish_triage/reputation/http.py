"""Policy-enforcing HTTP client for reputation lookups.

Every request must match an (method, host, path-prefix) endpoint declared by the
provider; HTTPS only; redirects refused; responses size-capped; every attempt is
written to the audit log (endpoint + defanged indicator - never API keys or queries).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlencode, urlsplit

from .. import __version__
from ..safety import defang

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
USER_AGENT = f"phish-triage/{__version__} (lookup-only)"


class PolicyViolation(Exception):
    """A request was blocked by the approved-source policy."""


@dataclass(frozen=True)
class Endpoint:
    method: str
    host: str
    path_prefix: str


@dataclass
class HttpResponse:
    status: int
    body: bytes

    def json(self) -> dict:
        try:
            data = json.loads(self.body.decode("utf-8", "replace") or "{}")
            return data if isinstance(data, dict) else {"_list": data}
        except json.JSONDecodeError:
            return {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise PolicyViolation(f"redirect to {urlsplit(newurl).hostname!r} refused")


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float) -> HttpResponse:
    """Default transport. Honors HTTPS_PROXY and system CA trust; never follows redirects."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            return HttpResponse(r.status, r.read(MAX_RESPONSE_BYTES))
    except urllib.error.HTTPError as e:
        return HttpResponse(e.code, e.read(MAX_RESPONSE_BYTES) if e.fp else b"")


Transport = Callable[[str, str, dict, "bytes | None", float], HttpResponse]


class GuardedClient:
    def __init__(self, source: str, endpoints: list[Endpoint], audit: list, timeout: float = 15,
                 transport: Transport | None = None):
        self.source = source
        self.endpoints = endpoints
        self.audit = audit
        self.timeout = timeout
        self.transport = transport or urllib_transport

    def _allowed(self, method: str, host: str, path: str) -> Endpoint | None:
        for e in self.endpoints:
            if e.method == method and e.host == host and path.startswith(e.path_prefix):
                return e
        return None

    def request(self, method: str, url: str, *, ioc: tuple[str, str], headers: dict | None = None,
                params: dict | None = None, form: dict | None = None, json_body: dict | None = None) -> HttpResponse:
        method = method.upper()
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params)
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        entry = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": self.source, "method": method, "endpoint": host,
            "ioc_type": ioc[0], "ioc": defang(ioc[1], ioc[0]), "status": None, "ms": None,
        }
        ep = self._allowed(method, host, p.path) if p.scheme == "https" else None
        if ep is None:
            entry["status"] = "blocked-by-policy"
            self.audit.append(entry)
            raise PolicyViolation(f"{method} https://{host}{p.path} is not an approved lookup endpoint for {self.source}")
        entry["endpoint"] = f"{host}{ep.path_prefix}"
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        hdrs.update(headers or {})
        body = None
        if form is not None:
            body = urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        t0 = time.monotonic()
        try:
            resp = self.transport(method, url, hdrs, body, self.timeout)
            entry["status"] = resp.status
            return resp
        except PolicyViolation:
            entry["status"] = "blocked-redirect"
            raise
        except Exception as e:
            entry["status"] = f"error:{type(e).__name__}"
            raise
        finally:
            entry["ms"] = int((time.monotonic() - t0) * 1000)
            self.audit.append(entry)
