"""Inert HTML inspection using the stdlib tokenizer.

The HTML is tokenized, never rendered: no scripts run, no remote resources load.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

URL_ATTRS = ("href", "src", "action", "formaction", "data", "background", "poster",
             "cite", "longdesc", "codebase", "lowsrc", "dynsrc", "xlink:href")

JS_TRAITS = {
    "atob(": "base64 decoding (atob)",
    "unescape(": "unescape()",
    "eval(": "eval()",
    "document.write": "document.write",
    "fromcharcode": "String.fromCharCode",
    "window.location": "scripted redirect (window.location)",
    "location.href": "scripted redirect (location.href)",
    "location.replace": "scripted redirect (location.replace)",
    "createobjecturl": "Blob URL creation (createObjectURL)",
    "new blob(": "Blob construction",
    "mssaveoropenblob": "msSaveOrOpenBlob",
    "xmlhttprequest": "XMLHttpRequest exfil",
    "fetch(": "fetch() exfil",
    "$.ajax(": "jQuery AJAX post",
    "sendbeacon": "navigator.sendBeacon",
}

MAX_TEXT = 200_000


@dataclass
class HtmlScan:
    links: list = field(default_factory=list)      # (url, tag, attr)
    anchors: list = field(default_factory=list)    # (href, visible text)
    forms: list = field(default_factory=list)      # {action, method, inputs, password}
    password_inputs: int = 0
    scripts: int = 0
    images: int = 0
    iframes: int = 0
    download_links: int = 0
    meta_refresh: list = field(default_factory=list)
    prefilled_values: list = field(default_factory=list)   # input value="..." that look like emails
    js_traits: list = field(default_factory=list)
    visible_text: str = ""
    script_text: str = ""


class _Scanner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.r = HtmlScan()
        self._anchors: list[list] = []
        self._form: dict | None = None
        self._skip: str | None = None
        self._text: list[str] = []
        self._tlen = 0
        self._script: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "").strip() for k, v in attrs if k}
        for k in URL_ATTRS:
            if a.get(k):
                self.r.links.append((a[k], tag, k))
        if a.get("srcset"):
            for cand in a["srcset"].split(","):
                if cand.strip():
                    self.r.links.append((cand.strip().split()[0], tag, "srcset"))
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\"\s;]+)", a.get("content", ""), re.I)
            if m:
                self.r.meta_refresh.append(m.group(1))
                self.r.links.append((m.group(1), "meta", "refresh"))
        if tag == "a":
            self._anchors.append([a.get("href", ""), []])
            if "download" in a:
                self.r.download_links += 1
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "inputs": [], "password": False}
            self.r.forms.append(self._form)
        elif tag == "input":
            t = (a.get("type") or "text").lower()
            if t == "password":
                self.r.password_inputs += 1
            if "@" in a.get("value", "") and len(self.r.prefilled_values) < 20:
                self.r.prefilled_values.append(a["value"][:120])
            if self._form is not None:
                self._form["inputs"].append(t)
                if t == "password":
                    self._form["password"] = True
        elif tag == "script":
            self.r.scripts += 1
            self._skip = "script"
        elif tag == "style":
            self._skip = "style"
        elif tag == "img":
            self.r.images += 1
        elif tag in ("iframe", "frame"):
            self.r.iframes += 1
        for k, v in a.items():  # inline event handlers are script too
            if k.startswith("on") and v:
                self._script.append(v)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in ("script", "style"):
            self._skip = None
        elif tag == "a":
            self.handle_endtag("a")

    def handle_endtag(self, tag):
        if tag == "a" and self._anchors:
            href, parts = self._anchors.pop()
            self.r.anchors.append((href, " ".join(" ".join(parts).split())[:300]))
        elif tag == "form":
            self._form = None
        elif tag in ("script", "style"):
            self._skip = None

    def handle_data(self, data):
        if self._skip == "script":
            self._script.append(data)
            return
        if self._skip == "style":
            return
        if self._tlen < MAX_TEXT:
            self._text.append(data)
            self._tlen += len(data)
        for item in self._anchors:
            if sum(len(x) for x in item[1]) < 600:
                item[1].append(data)


def scan_html(html: str) -> HtmlScan:
    p = _Scanner()
    try:
        p.feed(html or "")
        p.close()
    except Exception:  # malformed markup: keep whatever was tokenized
        pass
    while p._anchors:
        href, parts = p._anchors.pop()
        p.r.anchors.append((href, " ".join(" ".join(parts).split())[:300]))
    r = p.r
    r.visible_text = " ".join(" ".join(p._text).split())
    r.script_text = "\n".join(p._script)[:MAX_TEXT]
    low = r.script_text.lower()
    traits = {label for tok, label in JS_TRAITS.items() if tok in low}
    if r.download_links:
        traits.add("<a download> link (possible HTML smuggling)")
    r.js_traits = sorted(traits)
    return r
