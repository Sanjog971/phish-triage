"""Verdict scoring. Deliberately simple and explainable: capped sum of finding weights,
with reputation confirmation as the only path to a 'MALICIOUS' verdict."""
from __future__ import annotations

from dataclasses import dataclass

from .heuristics import Finding

MALWARE_IDS = {"ATTACHMENT_EXECUTABLE", "ATTACHMENT_DISK_IMAGE", "ATTACHMENT_ONENOTE", "ATTACHMENT_MACRO",
               "ATTACHMENT_ARCHIVE_RISKY", "HTML_SMUGGLING_TRAITS", "ATTACHMENT_RTLO"}
CRED_IDS = {"CREDENTIAL_FORM", "LINK_TEXT_MISMATCH", "LOOKALIKE_LINK_DOMAIN", "URL_RECIPIENT_TOKEN",
            "ATTACHMENT_HTML", "HTML_REDIRECT"}
SPOOF_IDS = {"INTERNAL_DOMAIN_SPOOF", "DMARC_FAIL", "DISPLAY_NAME_ADDRESS_SPOOF", "DISPLAY_NAME_BRAND",
             "LOOKALIKE_SENDER_DOMAIN", "AUTH_HEADER_INJECTION"}


@dataclass
class Verdict:
    label: str           # MALICIOUS | LIKELY MALICIOUS | SUSPICIOUS | LOW RISK
    score: int
    confidence: str
    categories: list


def categorize(findings: list[Finding], has_urls: bool, has_attachments: bool) -> list[str]:
    ids = {f.id for f in findings}
    cats = []
    if ids & MALWARE_IDS:
        cats.append("malware delivery")
    if ids & CRED_IDS or ("LURE_LANGUAGE" in ids and has_urls and ids & SPOOF_IDS):
        cats.append("credential phishing")
    if ids & {"REPLY_TO_FREEMAIL", "REPLY_TO_MISMATCH"} and not has_urls and not has_attachments:
        cats.append("BEC / reply-based fraud")
    if ids & SPOOF_IDS:
        cats.append("sender spoofing / impersonation")
    if "IMAGE_ONLY_BODY" in ids:
        cats.append("possible QR-code phishing")
    return cats


def score(findings: list[Finding], online_checked: bool, has_urls: bool, has_attachments: bool) -> Verdict:
    total = min(100, sum(f.weight for f in findings))
    ids = {f.id for f in findings}
    highs = sum(1 for f in findings if f.severity == "high" and f.id != "REPUTATION_MALICIOUS")
    cats = categorize(findings, has_urls, has_attachments)
    if "REPUTATION_MALICIOUS" in ids:
        return Verdict("MALICIOUS", max(total, 90), "high", cats)
    if total >= 60:
        return Verdict("LIKELY MALICIOUS", total, "high" if highs >= 3 else "medium", cats)
    if total >= 30:
        return Verdict("SUSPICIOUS", total, "medium" if highs else "low", cats)
    return Verdict("LOW RISK", total, "medium" if online_checked else "low", cats)
