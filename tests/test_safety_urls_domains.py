import base64

from phish_triage.domains import lookalike, registrable_domain
from phish_triage.safety import defang, is_reserved_domain, is_routable_ip, refang
from phish_triage.urls import find_urls, normalize_url, unwrap_url

PROTECTED = ["example.com", "microsoft.com", "paypal.com", "apple.com"]


def test_defang_refang_roundtrip():
    u = "https://login.evil.test/a.php?x=1"
    d = defang(u, "url")
    assert d == "hxxps://login[.]evil[.]test/a.php?x=1"
    assert refang(d) == u
    assert defang("a.b@evil.test", "email") == "a.b[@]evil[.]test"
    assert refang("hXXp://evil(.)test [at] x") == "http://evil.test @ x"


def test_userinfo_trick_is_visible_when_defanged():
    assert defang("http://paypal.com@evil.test/", "url") == "hxxp://paypal[.]com[@]evil[.]test/"


def test_reserved_and_routable():
    assert is_reserved_domain("mail.bulk-sender.test")
    assert is_reserved_domain("www.example.com")
    assert not is_reserved_domain("example-phish.com")
    assert not is_routable_ip("203.0.113.5")    # documentation range
    assert not is_routable_ip("10.1.2.3")
    assert is_routable_ip("8.8.8.8")


def test_find_urls_trims_punctuation():
    assert find_urls("see (https://evil.test/a).") == ["https://evil.test/a"]
    assert find_urls("go to www.evil.test/x, now") == ["www.evil.test/x"]


def test_normalize_idn_and_case():
    assert normalize_url("HTTPS://Evil.TEST/Path") == "https://evil.test/Path"
    assert normalize_url("https://exаmple.com/").startswith("https://xn--")
    assert normalize_url("javascript:alert(1)") is None


def test_unwrap_safelinks():
    wrapped = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.test%2Flogin%3Fa%3D1"
               "&data=05%7C02&reserved=0")
    assert unwrap_url(wrapped) == ("https://evil.test/login?a=1", ["microsoft-safelinks"])


def test_unwrap_proofpoint_v2_and_v3():
    v2 = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.test_login.php-3Fid-3D1&d=DwMF&c=x"
    assert unwrap_url(v2)[0] == "https://evil.test/login.php?id=1"
    enc = base64.urlsafe_b64encode(b"?").decode().rstrip("=")
    v3 = f"https://urldefense.com/v3/__https://evil.test/login*id=1__;{enc}!!abc$"
    assert unwrap_url(v3)[0] == "https://evil.test/login?id=1"


def test_unwrap_nested_google_inside_safelinks():
    inner = "https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%253A%252F%252Fevil.test%252Fx"
    wrapped = f"https://nam02.safelinks.protection.outlook.com/?url={inner}&data=1"
    final, chain = unwrap_url(wrapped)
    assert final == "https://evil.test/x"
    assert chain == ["microsoft-safelinks", "google-redirect"]


def test_registrable_domain():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("mail.bulk-sender.test") == "bulk-sender.test"
    assert registrable_domain("attacker.github.io") == "attacker.github.io"
    assert registrable_domain("x.y.blob.core.windows.net") == "y.blob.core.windows.net"


def test_lookalike_kinds():
    assert lookalike("rnicrosoft.com", PROTECTED)["kind"] == "homoglyph"
    assert lookalike("paypa1.com", PROTECTED)["kind"] == "homoglyph"
    assert lookalike("paypall.com", PROTECTED)["kind"] == "typosquat"
    assert lookalike("microsoft-login.test", PROTECTED)["kind"] == "embedded-brand"
    assert lookalike("examp1e-sso.test", PROTECTED)["kind"] == "embedded-homoglyph"
    assert lookalike("example.co", PROTECTED)["kind"] == "tld-swap"
    cyr = "аpple.com".encode("idna").decode()       # Cyrillic 'а'
    assert lookalike(cyr, PROTECTED)["kind"] == "homoglyph"
    assert lookalike("login.microsoft.com", PROTECTED) is None
    assert lookalike("vendor.test", PROTECTED) is None
