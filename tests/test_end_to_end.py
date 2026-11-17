import json
import re

from phish_triage.cli import main

from .conftest import ROOT


def run(tmp_path, *extra):
    out = tmp_path / "reports"
    rc = main(["analyze", str(ROOT / "samples"), "-c", str(ROOT / "config" / "triage.toml"),
               "-o", str(out), "-q", *extra])
    return rc, out


def test_batch_verdicts_and_outputs(tmp_path):
    rc, out = run(tmp_path)
    assert rc == 0
    verdicts = {}
    for case in out.iterdir():
        assert {p.name for p in case.iterdir()} == {"report.md", "report.json", "iocs.csv", "hunt.kql"}
        data = json.loads((case / "report.json").read_text())
        verdicts[data["sample"]["file"]] = data["verdict"]["label"]
    assert verdicts == {
        "01_credential_phish_internal_spoof.eml": "MALICIOUS",
        "02_reported_html_attachment.eml": "LIKELY MALICIOUS",
        "03_benign_vendor_newsletter.eml": "LOW RISK",
    }


def test_reports_are_defanged_and_redacted(tmp_path):
    _, out = run(tmp_path)
    for md in out.glob("*/report.md"):
        text = md.read_text()
        assert not re.search(r"\bhttps?://", text), md
        assert "examp1e-sso.test" not in text and "203.0.113.45" not in text
        assert "john.doe@example.com" not in text and "jane.doe@example.com" not in text
    for js in out.glob("*/report.json"):
        data = json.loads(js.read_text())
        assert all(a.startswith(("j***@",)) for a in data["message"]["to"])


def test_offline_audit_is_empty(tmp_path):
    _, out = run(tmp_path)
    for js in out.glob("*/report.json"):
        rep = json.loads(js.read_text())["reputation"]
        assert rep["audit"] == [] and rep["mode"].startswith("offline")


def test_case_id_and_formats(tmp_path):
    out = tmp_path / "r"
    rc = main(["analyze", str(ROOT / "samples" / "03_benign_vendor_newsletter.eml"), "-c",
               str(ROOT / "config" / "triage.toml"), "-o", str(out), "-q", "--case-id", "IR-42", "--format", "md"])
    assert rc == 0 and [p.name for p in (out / "IR-42").iterdir()] == ["report.md"]


def test_sources_and_defang_commands(capsys):
    assert main(["sources", "-c", str(ROOT / "config" / "triage.toml")]) == 0
    s = capsys.readouterr().out
    assert "virustotal" in s and "never sent externally" in s
    main(["defang", "https://evil.test/x"])
    assert capsys.readouterr().out.strip() == "hxxps://evil[.]test/x"
