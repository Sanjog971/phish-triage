from phish_triage.indicators import extract_indicators
from phish_triage.parse import parse_file


def test_sample1_indicators(cfg, samples):
    pe = parse_file(samples / "01_credential_phish_internal_spoof.eml", cfg)
    S = extract_indicators(pe, cfg)
    urls = {i.value: i for i in S.of_type("url")}
    target = "https://examp1e-sso.test/owa/auth?uid=REDACTED#am9obi5kb2VAZXhhbXBsZS5jb20="
    ind = urls[target]
    # same URL found in defanged plain text and in the Safe Links-wrapped HTML link -> one indicator
    assert "text body" in ind.sources and "HTML a.href" in ind.sources
    assert "unwrapped:microsoft-safelinks" in ind.tags
    assert "recipient-identifier" in ind.tags and ind.display.endswith("#[recipient-id]")
    # anchor text that merely *looks* like a URL is not an indicator
    assert not any("portal.example.com" in u for u in urls)
    # victims are never indicators
    assert not any(i.value == "john.doe@example.com" for i in S.of_type("email"))
    # sanitized infrastructure is never eligible for external lookup
    assert all(not i.lookup_eligible for i in S.all())
    assert S.get("ip", "203.0.113.45").skip_reason.startswith("non-routable")
    assert S.get("email", "it.servicedesk.verify@freemail.test").skip_reason.startswith("email addresses")


def test_internal_and_benign_hidden(cfg, samples):
    pe = parse_file(samples / "03_benign_vendor_newsletter.eml", cfg)
    S = extract_indicators(pe, cfg)
    assert not any("w3.org" in i.value for i in S.all())
    assert S.get("domain", "vendor.test") is not None
