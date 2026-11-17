import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phish_triage.config import load_config  # noqa: E402
from phish_triage.reputation.http import HttpResponse  # noqa: E402

SAMPLES = ROOT / "samples"


@pytest.fixture
def cfg():
    return load_config(ROOT / "config" / "triage.toml")


@pytest.fixture
def samples():
    return SAMPLES


class FakeTransport:
    """Records every request; answers from a routing table {(method, host, path_prefix): fn|HttpResponse}."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        from urllib.parse import urlsplit
        p = urlsplit(url)
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        for (m, host, prefix), resp in self.routes.items():
            if m == method and host == p.hostname and p.path.startswith(prefix):
                return resp(method, url, headers, body) if callable(resp) else resp
        return HttpResponse(404, b"{}")


def jresp(obj, status=200):
    return HttpResponse(status, json.dumps(obj).encode())


@pytest.fixture
def fake():
    return FakeTransport()
