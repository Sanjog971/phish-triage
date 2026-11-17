import time

import pytest

from phish_triage.heuristics import evaluate
from phish_triage.indicators import IndicatorSet, classify
from phish_triage.parse import parse_bytes
from phish_triage.reputation import ReputationEngine
from phish_triage.reputation.http import Endpoint, GuardedClient, PolicyViolation, _NoRedirect

from .conftest import FakeTransport, jresp

KEYS = {"VT_API_KEY": "vt-secret", "ABUSEIPDB_API_KEY": "aipdb-secret",
        "ABUSECH_AUTH_KEY": "abusech-secret", "GSB_API_KEY": "gsb-secret"}


@pytest.fixture
def online_cfg(tmp_path, monkeypatch, cfg):
    for k, v in KEYS.items():
        monkeypatch.setenv(k, v)
    for name in ("virustotal", "abuseipdb", "urlhaus", "threatfox", "malwarebazaar", "google_safe_browsing"):
        cfg.sources[name]["enabled"] = True
        cfg.sources[name]["requests_per_minute"] = 0
    cfg.rep["cache_path"] = str(tmp_path / "cache.json")
    return cfg


def _iocs(cfg, recipients=()):
    S = IndicatorSet()
    u = S.add("url", "https://login-paypa1-secure.com/signin?session=abc#frag", "HTML a.href")
    u.meta = {"host": "login-paypa1-secure.com"}
    S.add("domain", "login-paypa1-secure.com", "link host")
    S.add("ip", "45.33.32.156", "origin IP")
    S.add("sha256", "a" * 64, "attachment x.html")
    S.add("email", "attacker@login-paypa1-secure.com", "Reply-To")
    S.add("ip", "203.0.113.9", "link host")          # documentation range -> never sent
    S.add("domain", "intranet.example.com", "link host")  # internal -> never sent
    classify(S, cfg)
    return S


def full_routes():
    vt_stats = {"data": {"id": "deadbeef", "attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20},
        "creation_date": int(time.time()) - 5 * 86400}}}
    return {
        ("GET", "www.virustotal.com", "/api/v3/"): jresp(vt_stats),
        ("GET", "api.abuseipdb.com", "/api/v2/check"): jresp({"data": {
            "abuseConfidenceScore": 88, "totalReports": 41, "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting", "countryCode": "NL", "isTor": False}}),
        ("POST", "urlhaus-api.abuse.ch", "/v1/url/"): jresp({"query_status": "ok", "threat": "malware_download",
                                                             "url_status": "online", "tags": ["phish"],
                                                             "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}),
        ("POST", "urlhaus-api.abuse.ch", "/v1/host/"): jresp({"query_status": "no_results"}),
        ("POST", "urlhaus-api.abuse.ch", "/v1/payload/"): jresp({"query_status": "no_results"}),
        ("POST", "threatfox-api.abuse.ch", "/api/v1/"): jresp({"query_status": "no_result"}),
        ("POST", "mb-api.abuse.ch", "/api/v1/"): jresp({"query_status": "ok", "data": [
            {"signature": "Phishing-HTML", "file_type": "html", "tags": ["html"]}]}),
        ("POST", "safebrowsing.googleapis.com", "/v4/threatMatches:find"): jresp(
            {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}),
    }


def test_offline_makes_no_requests(online_cfg):
    t = FakeTransport(full_routes())
    eng = ReputationEngine(online_cfg, online=False, transport=t)
    eng.enrich(_iocs(online_cfg).all())
    assert t.calls == [] and eng.audit == []
    assert all("offline" in why for _, why in eng.skipped)


def test_unapproved_and_keyless_sources_are_skipped(online_cfg, monkeypatch):
    online_cfg.sources["virustotal"]["enabled"] = False
    monkeypatch.delenv("ABUSEIPDB_API_KEY")
    t = FakeTransport(full_routes())
    eng = ReputationEngine(online_cfg, online=True, transport=t)
    eng.enrich(_iocs(online_cfg).all())
    hosts = {c["url"].split("/")[2] for c in t.calls}
    assert "www.virustotal.com" not in hosts and "api.abuseipdb.com" not in hosts
    skipped = dict(eng.skipped)
    assert "not approved" in skipped["virustotal"] and "ABUSEIPDB_API_KEY" in skipped["abuseipdb"]


def test_online_lookups_respect_eligibility_and_parse_results(online_cfg):
    t = FakeTransport(full_routes())
    eng = ReputationEngine(online_cfg, online=True, transport=t)
    S = _iocs(online_cfg)
    eng.enrich(S.all())
    sent = " ".join(str(c["url"]) + str(c["body"]) for c in t.calls)
    assert "203.0.113.9" not in sent and "intranet.example.com" not in sent and "attacker" not in sent
    assert "#frag" not in sent and "frag" not in sent        # strip_fragment default

    url = S.get("url", "https://login-paypa1-secure.com/signin?session=abc#frag")
    st = {r.source: r.status for r in url.reputation}
    assert st == {"virustotal": "malicious", "urlhaus": "malicious", "threatfox": "not_found",
                  "google_safe_browsing": "malicious"}
    ip = S.get("ip", "45.33.32.156")
    assert {r.source: r.status for r in ip.reputation}["abuseipdb"] == "malicious"
    dom = next(r for r in S.get("domain", "login-paypa1-secure.com").reputation if r.source == "virustotal")
    assert dom.data["domain_age_days"] in (4, 5)
    h = S.get("sha256", "a" * 64)
    assert {r.source: r.status for r in h.reputation}["malwarebazaar"] == "malicious"

    # API keys go in headers / query only, and never into the audit trail
    audit = str(eng.audit)
    assert not any(k in audit for k in KEYS.values())
    assert any(c["headers"].get("x-apikey") == "vt-secret" for c in t.calls)
    assert all(e["status"] == 200 for e in eng.audit)


def test_recipient_identifier_urls_are_stripped(online_cfg):
    t = FakeTransport(full_routes())
    online_cfg.data["sources"] = {k: v for k, v in online_cfg.sources.items() if k in ("urlhaus", "local_intel")}
    eng = ReputationEngine(online_cfg, online=True, transport=t)
    S = IndicatorSet()
    u = S.add("url", "https://evil-host.com/p?id=am9obkBleGFtcGxlLmNvbQ", "HTML a.href")
    u.meta = {"host": "evil-host.com"}
    u.tag("recipient-identifier")
    eng.enrich([u])
    assert t.calls[0]["body"] == b"url=https%3A%2F%2Fevil-host.com%2Fp"
    assert "stripped" in u.reputation[0].summary


def test_share_policy_limits_types(online_cfg):
    t = FakeTransport(full_routes())
    online_cfg.sources["virustotal"]["share"] = ["sha256"]
    eng = ReputationEngine(online_cfg, online=True, only={"virustotal"}, transport=t)
    eng.enrich(_iocs(online_cfg).all())
    assert [c["url"].split("/api/v3/")[1].split("/")[0] for c in t.calls] == ["files"]


def test_cache_prevents_repeat_requests(online_cfg):
    t = FakeTransport(full_routes())
    ReputationEngine(online_cfg, online=True, only={"abuseipdb"}, transport=t).enrich(_iocs(online_cfg).all())
    assert len(t.calls) == 1
    S = _iocs(online_cfg)
    ReputationEngine(online_cfg, online=True, only={"abuseipdb"}, transport=t).enrich(S.all())
    assert len(t.calls) == 1 and S.get("ip", "45.33.32.156").reputation[0].cached


def test_budget_caps_requests(online_cfg):
    t = FakeTransport(full_routes())
    eng = ReputationEngine(online_cfg, online=True, transport=t, use_cache=False, max_lookups=2)
    eng.enrich(_iocs(online_cfg).all())
    assert len(t.calls) == 2 and any("budget" in n for n in eng.notes)


def test_http_errors_become_error_results(online_cfg):
    t = FakeTransport({("GET", "api.abuseipdb.com", "/api/v2/check"): jresp({}, status=401)})
    eng = ReputationEngine(online_cfg, online=True, only={"abuseipdb"}, transport=t, use_cache=False)
    S = _iocs(online_cfg)
    eng.enrich(S.all())
    r = S.get("ip", "45.33.32.156").reputation[0]
    assert r.status == "error" and "authentication failed" in r.summary


def test_guarded_client_blocks_unapproved_endpoints():
    audit = []
    c = GuardedClient("virustotal", [Endpoint("GET", "www.virustotal.com", "/api/v3/files/")], audit,
                      transport=FakeTransport())
    with pytest.raises(PolicyViolation):   # URL *submission* is not a declared endpoint
        c.request("POST", "https://www.virustotal.com/api/v3/urls", ioc=("url", "https://x.test/"))
    with pytest.raises(PolicyViolation):   # plain HTTP
        c.request("GET", "http://www.virustotal.com/api/v3/files/abc", ioc=("sha256", "abc"))
    with pytest.raises(PolicyViolation):   # other host
        c.request("GET", "https://evil.test/api/v3/files/abc", ioc=("sha256", "abc"))
    assert [e["status"] for e in audit] == ["blocked-by-policy"] * 3


def test_redirects_are_refused():
    with pytest.raises(PolicyViolation):
        _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.test/")


def test_reputation_drives_verdict_findings(online_cfg):
    raw = (b"From: a@login-paypa1-secure.com\r\nTo: john.doe@example.com\r\nSubject: hi\r\n\r\n"
           b"https://login-paypa1-secure.com/signin\r\n")
    pe = parse_bytes(raw, online_cfg)
    from phish_triage.indicators import extract_indicators
    S = extract_indicators(pe, online_cfg)
    ReputationEngine(online_cfg, online=True, only={"virustotal"}, transport=FakeTransport(full_routes()),
                     use_cache=False).enrich(S.all())
    found = {f.id for f in evaluate(pe, S, online_cfg)}
    assert {"REPUTATION_MALICIOUS", "YOUNG_DOMAIN", "LOOKALIKE_SENDER_DOMAIN"} <= found


def test_local_intel_only_when_offline(cfg):
    eng = ReputationEngine(cfg, online=False)
    S = IndicatorSet()
    u = S.add("url", "https://a.examp1e-sso.test/x", "t")
    u.meta = {"host": "a.examp1e-sso.test"}
    eng.enrich([u])
    assert u.reputation[0].source == "local_intel" and u.reputation[0].status == "malicious"
