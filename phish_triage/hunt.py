"""Microsoft Defender XDR (advanced hunting) queries to scope a campaign."""
from __future__ import annotations

from .indicators import IndicatorSet
from .parse import ParsedEmail


def _q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _list(values) -> str:
    return "(" + ", ".join(_q(v) for v in values) + ")"


def build_kql(case_id: str, pe: ParsedEmail, iocs: IndicatorSet, days: int = 14) -> str:
    ago = f"ago({days}d)"
    L = [f"// Hunt queries for {case_id} - Microsoft Defender XDR advanced hunting",
         "// Values below are LIVE (not defanged). They are query strings, not links.",
         f"// Window: last {days} days. Review each query before running.", ""]

    sender = pe.from_.addr if pe.from_ else None
    conds = []
    if pe.message_id:
        conds.append(f"InternetMessageId == {_q(pe.message_id)}")
    if sender and pe.subject:
        conds.append(f"(SenderFromAddress =~ {_q(sender)} and Subject == {_q(pe.subject)})")
    if conds:
        L += ["// 1. Delivery scope: every copy of this message / campaign",
              "EmailEvents", f"| where Timestamp > {ago}", "| where " + "\n    or ".join(conds),
              "| summarize Recipients = dcount(RecipientEmailAddress), RecipientList = make_set(RecipientEmailAddress, 200),",
              "    Actions = make_set(DeliveryAction), Locations = make_set(DeliveryLocation),",
              "    FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by SenderFromAddress, Subject, SenderIPv4", ""]

    if pe.origin_ip and "." in pe.origin_ip:
        L += ["// 2. Other mail from the same sending IP",
              "EmailEvents", f"| where Timestamp > {ago}", f"| where SenderIPv4 == {_q(pe.origin_ip)}",
              "| summarize Messages = count(), Senders = make_set(SenderFromAddress, 50), Subjects = make_set(Subject, 50)", ""]

    domains = sorted({i.meta.get("host") for i in iocs.of_type("url")
                      if not i.hidden and "freemail" not in i.tags and i.meta.get("host")})
    if domains:
        L += ["// 3. Messages containing links to these hosts",
              "EmailUrlInfo", f"| where Timestamp > {ago}", f"| where UrlDomain in~ {_list(domains)}",
              f"| join kind=inner (EmailEvents | where Timestamp > {ago}) on NetworkMessageId",
              "| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, DeliveryLocation", "",
              "// 4. Who clicked (Safe Links click telemetry)",
              "UrlClickEvents", f"| where Timestamp > {ago}", f"| where Url has_any {_list(domains)}",
              "| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress", ""]

    hashes = [a.sha256 for a in pe.attachments if a.detected_type != "message/rfc822"]
    if hashes:
        L += ["// 5. Attachment delivery and presence on endpoints",
              "EmailAttachmentInfo", f"| where Timestamp > {ago}", f"| where SHA256 in {_list(hashes)}",
              "| project Timestamp, RecipientEmailAddress, SenderFromAddress, FileName, SHA256", "",
              "DeviceFileEvents", f"| where Timestamp > {ago}", f"| where SHA256 in {_list(hashes)}",
              "| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName", ""]

    reply_to = sorted({a.addr for a in pe.reply_to if a.addr and (not pe.from_ or a.addr != pe.from_.addr)})
    if reply_to:
        L += ["// 6. Did anyone reply to the Reply-To address?",
              "EmailEvents", f"| where Timestamp > {ago}", '| where EmailDirection == "Outbound"',
              f"| where RecipientEmailAddress in~ {_list(reply_to)}",
              "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject", ""]
    return "\n".join(L).rstrip() + "\n"
