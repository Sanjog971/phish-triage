"""report.md must stay inert whatever the email contains: no links, images, raw HTML,
autolinks, @-mentions or broken table structure, in any common Markdown renderer."""
import base64
import json
import re
from urllib.parse import quote

import pytest

from phish_triage.cli import main
from phish_triage.mdsafe import md_text
from phish_triage.parse import parse_bytes

from .conftest import ROOT

HOSTILE_SUBJECT = (
    "[click](https://evil.test/s) <img src=x onerror=alert(1)> ![p](https://evil.test/p.png) "
    "<https://evil.test/auto> www.evil-site.com reach evil@attacker.test `code` | **bold** "
    "<script>alert(1)</script> &lt;b&gt; $x$ ~~s~~ visit paypal-login.com \\"
)
HOSTILE_FILENAME = "x`](https://evil.test/f)`<img src=x>|‮gnp.html"


def hostile_eml() -> bytes:
    att = base64.b64encode(b"<html><body>hi</body></html>").decode()
    encoded_filename = quote(HOSTILE_FILENAME, safe="")
    raw = (
        "Authentication-Results: mx01.example.com; spf=pass smtp.mailfrom=x.test; dkim=none; "
        "dmarc=fail action=<img/src=x> header.from=[pwn](https://evil.test/a)\n"
        "Received: from mail.evil.test (mail.evil.test [203.0.113.9]) by <b>mx</b>.example.com "
        "with ESMTPS id 1; Tue, 17 Nov 2026 08:12:07 +0000\n"
        "From: \"<a href='https://evil.test/dn'>IT</a> [x](javascript:alert(1)) @admin\" <attacker@evil.test>\n"
        "To: john.doe@example.com\n"
        f"Subject: {HOSTILE_SUBJECT}\n"
        "Message-ID: <a`b](https://evil.test/m)`@evil.test>\n"
        "Date: Tue, 17 Nov 2026 08:12:01 +0000\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="b"\n\n'
        "--b\nContent-Type: text/html\n\n"
        '<a href="https://evil.test/x`y|z<q>">open</a>\n'
        f"--b\nContent-Type: text/html; name*=utf-8''{encoded_filename}\n"
        f"Content-Disposition: attachment; filename*=utf-8''{encoded_filename}\n"
        "Content-Transfer-Encoding: base64\n\n"
        f"{att}\n--b--\n"
    )
    return raw.replace("\n", "\r\n").encode()


@pytest.fixture
def hostile_report(tmp_path):
    eml = tmp_path / "hostile.eml"
    eml.write_bytes(hostile_eml())
    out = tmp_path / "out"
    assert main(["analyze", str(eml), "-c", str(ROOT / "config" / "triage.toml"), "-o", str(out),
                 "-q", "--case-id", "HOSTILE"]) == 0
    return (
        (out / "HOSTILE" / "report.md").read_text(encoding="utf-8"),
        json.loads((out / "HOSTILE" / "report.json").read_text(encoding="utf-8")),
    )


# ---------------------------------------------------------------------------- encoder unit tests

def test_md_text_neutralises_markdown_and_html():
    s = md_text("[a](https://x.test) ![i](y) <b>&amp; `c` *e* _u_ ~~s~~ $m$ |pipe\\")
    assert "<" not in s and ">" not in s
    assert re.search(r"(?<!\\)[\[\]()`*_~|$!]", s) is None      # every metacharacter escaped
    assert "&amp;amp;" in s and "hxxps:" in s and "x\\[.\\]test" in s


def test_md_text_defangs_autolink_shapes():
    s = md_text("http://a.test www.b.test c@d.test javascript:x mailto:e 10.1.2.3 evil.com @team")
    for live in ("http:", "www.", "@d", "javascript:", "mailto:", "10.1", "evil.com", " @team"):
        assert live not in s, live
    assert "evil\\[.\\]com" in s and "javascript\\[:\\]" in s and "\\[@\\]team" in s


def test_md_text_makes_hidden_characters_visible():
    s = md_text("invoice‮fdp.exe zero​width line\nbreak\x00nul")
    assert "‮" not in s and "​" not in s and "\x00" not in s and "\n" not in s
    assert "\\[U+202E\\]" in s and "\\[U+200B\\]" in s


def test_md_text_is_idempotent_on_defanged_values():
    once = md_text("hxxps://evil[.]test/a x[@]y[.]test 203[.]0[.]113[.]9")
    assert "\\[\\[" not in once                      # no double-defanging like [[.]]
    assert once == "hxxps://evil\\[.\\]test/a x\\[@\\]y\\[.\\]test 203\\[.\\]0\\[.\\]113\\[.\\]9"


def test_md_text_leaves_email_local_parts_alone():
    assert md_text("john.doe@evil.com") == "john.doe\\[@\\]evil\\[.\\]com"


def test_md_text_caps_length():
    assert len(md_text("a" * 10_000)) < 2_100


# ---------------------------------------------------------------------------- end-to-end invariants

def test_hostile_report_source_is_inert(hostile_report):
    md, _ = hostile_report
    assert set(re.findall(r"<[^>]*>", md)) <= {"<br>"}                    # no raw HTML / <autolinks>
    assert re.search(r"(?<!\\)[\[\]]", md) is None                        # no link/image brackets
    assert re.search(r"(?i)\b(?:https?|ftp|javascript|data|vbscript|mailto):", md) is None
    assert re.search(r"(?i)\bwww\.", md) is None
    assert re.search(r"(?<!\[)@", md) is None                              # no autolinked email / @mention
    assert "‮" not in md and "[U+202E]" in md.replace("\\", "")      # RTLO shown, not applied
    for bad in ("<img", "<script", "<a ", "](http", "paypal-login.com", "evil.test"):
        assert bad not in md, bad


def test_hostile_report_code_spans_and_tables_are_balanced(hostile_report):
    md, _ = hostile_report
    columns = None
    for line in md.splitlines():
        assert len(re.findall(r"(?<!\\)`", line)) % 2 == 0, line          # untrusted ` cannot open a span
        if line.startswith("|"):
            cells = len(re.findall(r"(?<!\\)\|", line))
            if re.match(r"^\|[-|]+\|$", line):
                columns = cells
            elif columns is not None and not line.startswith("| |"):
                assert cells == columns, line                               # untrusted | cannot add a column
        else:
            columns = None


def test_hostile_values_survive_losslessly_in_json(hostile_report):
    _, data = hostile_report
    assert data["message"]["subject"] == HOSTILE_SUBJECT
    assert data["attachments"][0]["filename"] == HOSTILE_FILENAME
    assert data["message"]["message_id"] == "<a`b](https://evil.test/m)`@evil.test>"


def test_message_id_kept_raw_for_hunting(cfg):
    pe = parse_bytes(hostile_eml(), cfg)
    assert pe.message_id == "<a`b](https://evil.test/m)`@evil.test>"   # stdlib parser would truncate it


@pytest.mark.parametrize("preset", ["commonmark", "gfm-like"])
def test_hostile_report_renders_without_links_or_html(hostile_report, preset):
    markdown_it = pytest.importorskip("markdown_it")
    if preset == "gfm-like":
        pytest.importorskip("linkify_it")
    html = markdown_it.MarkdownIt(preset).render(hostile_report[0])   # gfm-like: raw HTML + linkify on
    assert re.findall(r'<[^>]*\b(?:href|src)\s*=', html) == []        # attributes inside real tags only
    allowed = {"h1", "h2", "p", "table", "thead", "tbody", "tr", "th", "td", "strong", "em",
               "code", "ol", "ul", "li", "br"}
    assert {t.lower() for t in re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", html)} <= allowed


def test_bundled_sample_reports_render_without_links(tmp_path):
    markdown_it = pytest.importorskip("markdown_it")
    pytest.importorskip("linkify_it")
    out = tmp_path / "r"
    main(["analyze", str(ROOT / "samples"), "-c", str(ROOT / "config" / "triage.toml"), "-o", str(out), "-q"])
    for md in out.glob("*/report.md"):
        html = markdown_it.MarkdownIt("gfm-like").render(md.read_text())
        assert re.findall(r'<[^>]*\b(?:href|src)\s*=', html) == [], md
