import hashlib
import io
import zipfile
from email.message import EmailMessage

import pytest

from phish_triage.config import load_config
from phish_triage.heuristics import evaluate
from phish_triage.indicators import extract_indicators
from phish_triage.parse import InputRejected, parse_bytes, parse_file


def ids(pe, cfg):
    return {f.id for f in evaluate(pe, extract_indicators(pe, cfg), cfg)}


def test_trusted_auth_results_and_injected_header(cfg, samples):
    pe = parse_file(samples / "01_credential_phish_internal_spoof.eml", cfg)
    a = pe.auth
    assert a.trusted and a.authserv_id == "mx01.example.com"
    assert (a.spf, a.dmarc, a.dmarc_policy) == ("pass", "fail", "quarantine")
    assert a.spf_domain == "mailer.bulk-sender.test"
    assert [i["authserv_id"] for i in a.ignored] == ["mail.bulk-sender.test"]


def test_trust_boundary_origin(cfg, samples):
    pe = parse_file(samples / "01_credential_phish_internal_spoof.eml", cfg)
    assert pe.origin_ip == "203.0.113.45" and pe.origin_method.startswith("trust boundary")
    assert pe.earliest_claimed_ip == "198.51.100.200"
    assert [h.delay_s for h in reversed(pe.hops)] == [None, 4.0, 2.0]


def test_without_trust_config_everything_is_unverified(samples):
    bare = load_config(None)
    pe = parse_file(samples / "01_credential_phish_internal_spoof.eml", bare)
    assert not pe.auth.trusted and "not verified" in pe.auth.note
    assert pe.origin_ip == "198.51.100.200" and "unverified" in pe.origin_method


def test_sample1_findings(cfg, samples):
    pe = parse_file(samples / "01_credential_phish_internal_spoof.eml", cfg)
    assert pe.subject == "Action required: your mailbox password expires today"
    found = ids(pe, cfg)
    for expected in ("INTERNAL_DOMAIN_SPOOF", "DMARC_FAIL", "LINK_TEXT_MISMATCH", "LOOKALIKE_LINK_DOMAIN",
                     "REPLY_TO_FREEMAIL", "AUTH_HEADER_INJECTION", "URL_IP_LITERAL", "URL_RECIPIENT_TOKEN",
                     "LURE_LANGUAGE"):
        assert expected in found, expected


def test_reported_message_is_unwrapped(cfg, samples):
    pe = parse_file(samples / "02_reported_html_attachment.eml", cfg)
    assert pe.unwrapped_from["reporter"] == "jane.doe@example.com"
    assert pe.from_.addr == "ap@northwind-billing.test"
    (att,) = pe.attachments
    assert att.filename == "Remittance_Advice_44817.pdf.html" and att.detected_type == "html"
    assert att.html.forms[0]["password"] and "base64 decoding (atob)" in att.html.js_traits
    found = ids(pe, cfg)
    assert {"ATTACHMENT_DOUBLE_EXTENSION", "CREDENTIAL_FORM", "HTML_SMUGGLING_TRAITS",
            "PREFILLED_RECIPIENT", "ATTACHMENT_HTML"} <= found
    assert "DMARC_FAIL" not in found     # authenticated mail can still be malicious


def test_no_unwrap_analyzes_reporter_envelope(cfg, samples):
    cfg.analysis["unwrap_reported_messages"] = False
    pe = parse_file(samples / "02_reported_html_attachment.eml", cfg)
    assert pe.from_.addr == "jane.doe@example.com"
    assert pe.attachments[0].detected_type == "message/rfc822"


def test_benign_newsletter_has_no_findings(cfg, samples):
    pe = parse_file(samples / "03_benign_vendor_newsletter.eml", cfg)
    assert ids(pe, cfg) == set()


def test_microsoft_style_auth_results_with_topmost(cfg):
    raw = (b"Authentication-Results: spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=evil.test; "
           b"dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine "
           b"header.from=example.com;compauth=fail reason=000\r\n"
           b"From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nhi\r\n")
    cfg.org["trusted_authserv_ids"] = ["topmost"]
    pe = parse_bytes(raw, cfg)
    assert pe.auth.trusted and pe.auth.authserv_id is None
    assert (pe.auth.dmarc, pe.auth.dmarc_policy, pe.auth.compauth) == ("fail", "quarantine", "fail")
    assert pe.auth.dkim_result == "none"


def test_size_limit_rejects_without_parsing(cfg, tmp_path):
    cfg.analysis["max_email_bytes"] = 100
    p = tmp_path / "big.eml"
    p.write_bytes(b"Subject: x\r\n\r\n" + b"A" * 500)
    with pytest.raises(InputRejected):
        parse_file(p, cfg)


def _msg_with(filename, payload, ctype="application/octet-stream"):
    m = EmailMessage()
    m["From"] = "billing@vendor-invoices.test"
    m["To"] = "john.doe@example.com"
    m["Subject"] = "Invoice"
    m.set_content("see attached")
    maintype, subtype = ctype.split("/")
    m.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return m.as_bytes()


def test_disguised_executable(cfg):
    payload = b"MZ\x90\x00" + b"\x00" * 200
    pe = parse_bytes(_msg_with("invoice.pdf", payload), cfg)
    att = pe.attachments[0]
    assert att.detected_type == "pe-executable"
    assert att.sha256 == hashlib.sha256(payload).hexdigest()
    found = ids(pe, cfg)
    assert {"ATTACHMENT_EXECUTABLE", "ATTACHMENT_TYPE_MISMATCH"} <= found


def test_zip_listed_not_extracted(cfg):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Invoice_2026.pdf.js", b"/* inert */")
    data = bytearray(buf.getvalue())
    cd = data.find(b"PK\x01\x02")          # set the "encrypted" bit in the central directory entry
    data[cd + 8] |= 0x1
    pe = parse_bytes(_msg_with("Invoice.zip", bytes(data)), cfg)
    att = pe.attachments[0]
    assert att.archive_entries == ["Invoice_2026.pdf.js"] and att.archive_encrypted
    assert {"ATTACHMENT_ENCRYPTED_ARCHIVE", "ATTACHMENT_ARCHIVE_RISKY"} <= ids(pe, cfg)


def test_macro_office_document(cfg):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", b"\x00")
    pe = parse_bytes(_msg_with("Q4.docm", buf.getvalue()), cfg)
    att = pe.attachments[0]
    assert att.detected_type == "ooxml" and att.has_macros
    assert "ATTACHMENT_MACRO" in ids(pe, cfg)


def test_display_name_spoof_and_brand(cfg):
    raw = (b'From: "ceo@example.com via Microsoft" <x@freemail.test>\r\nTo: john.doe@example.com\r\n'
           b"Subject: quick task\r\n\r\nAre you available? I need a favour.\r\n")
    found = ids(parse_bytes(raw, cfg), cfg)
    assert {"DISPLAY_NAME_ADDRESS_SPOOF", "DISPLAY_NAME_BRAND"} <= found


def test_link_traits_free_hosting_shortener_userinfo(cfg):
    raw = (b"From: it@helpdesk-portal.test\r\nTo: john.doe@example.com\r\nSubject: docs\r\n\r\n"
           b"https://m365-review.pages.dev/x https://bit.ly/3abc http://paypal.com@203.0.113.8/login\r\n")
    found = ids(parse_bytes(raw, cfg), cfg)
    assert {"URL_FREE_HOSTING", "URL_SHORTENER", "URL_USERINFO", "URL_IP_LITERAL"} <= found
