"""Encoding for untrusted text placed in the Markdown report.

Anything that came from the email (subject, names, filenames, header values, URLs) or from an
external API is attacker-influenced. `md_text()` makes it inert in CommonMark, GFM and
linkify-style renderers (GitHub, GitLab, VS Code preview, markdown-it, Obsidian):

1. hidden characters (bidi overrides, zero-width, control chars) become visible ``[U+XXXX]``;
2. URL schemes, ``www.``/bare domains, IPv4 addresses and ``@`` are defanged, so nothing
   autolinks and no @-mention fires;
3. Markdown punctuation is backslash-escaped: no links, images, emphasis, code spans,
   strikethrough, math or table breaks;
4. ``& < >`` become entities: no raw HTML and no ``<autolinks>``.

The function is idempotent on text that is already defanged (``[.]``, ``[@]``, ``hxxps://``),
so values defanged earlier in the pipeline can be passed through it safely.
"""
from __future__ import annotations

import re

MAX_LEN = 2000  # a report cell never needs more; also bounds regex work on hostile input

_HIDDEN = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f­؜᠎​-‏"
    r" -‮⁠-⁩﻿￹-￻]"
)
_SCHEME = re.compile(
    r"(?i)\b(https?|ftps?|sftp|file|smb|wss?|javascript|vbscript|data|mailto|xmpp|tel|sms|irc"
    r"|search-ms|ms-[a-z-]+)(:)(?!\])"
)
_FANG_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
_AT = re.compile(r"(?<!\[)@(?!\])")
_DOTS = ".。．｡"  # ASCII dot + the ideographic/full-width dots IDNA also accepts
_DOMAIN = re.compile(
    rf"(?<![\w-])(?:[^\W_](?:[\w-]{{0,61}}[^\W_])?[{_DOTS}])+"
    rf"(?:[^\W\d_]{{2,24}}|xn--[a-z0-9-]{{1,59}})"
    rf"(?![\w-]|[{_DOTS}][^\W_]|\[@\]|@)",  # whole name only; an email local part stays as-is
    re.I,
)
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_MD_PUNCT = re.compile(r"([\\`*_~\[\]()!|$])")


def _visible(m: re.Match) -> str:
    return f"[U+{ord(m.group(0)):04X}]"


def _scheme(m: re.Match) -> str:
    name = m.group(1)
    fanged = _FANG_SCHEMES.get(name.lower())
    return f"{fanged}:" if fanged else f"{name}[:]"


def _dots(m: re.Match) -> str:
    return re.sub(f"[{_DOTS}]", "[.]", m.group(0))


def defang_text(s: str) -> str:
    """Neutralise hidden characters and anything a renderer could turn into a link."""
    s = " ".join(str(s).split())
    s = _HIDDEN.sub(_visible, s)
    s = _SCHEME.sub(_scheme, s)
    s = _AT.sub("[@]", s)
    s = _DOMAIN.sub(_dots, s)
    s = _IPV4.sub(_dots, s)
    return s


def md_text(value, limit: int = MAX_LEN) -> str:
    """Untrusted value -> inert inline Markdown (safe inside table cells and list items)."""
    if value is None:
        return ""
    s = str(value)
    if len(s) > limit:
        s = s[:limit] + "…"
    s = defang_text(s)
    s = _MD_PUNCT.sub(r"\\\1", s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
