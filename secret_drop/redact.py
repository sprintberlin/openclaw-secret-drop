"""Keep secret bytes and URL key material out of logs, traces, and exceptions."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_FRAGMENT_RE = re.compile(r"#.*$", re.S)
_USERINFO_RE = re.compile(r"(://)([^/@]+)@")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def sanitize_url(url: str) -> str:
    """Drop fragment, userinfo, and common secret query keys. Keep scheme/host/path."""
    raw = (url or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        # Query values can carry passphrases or access tokens. Error messages do not
        # need them, so drop the whole query instead of trying to classify every key.
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        cleaned = _FRAGMENT_RE.sub("# [redacted]", raw)
        cleaned = _USERINFO_RE.sub(r"\1[redacted]@", cleaned)
        return cleaned


def redact_text(text: str, *, secret: str | None = None, url: str | None = None) -> str:
    out = text or ""
    if secret:
        if secret in out:
            out = out.replace(secret, "[redacted-secret]")
        trimmed = secret.strip()
        if trimmed and trimmed in out:
            out = out.replace(trimmed, "[redacted-secret]")
        # Redact common token prefixes or substrings if longer than 8 chars
        if len(trimmed) > 8:
            # Check for chunked or partial representations
            chunk_len = max(8, len(trimmed) // 2)
            out = out.replace(trimmed[:chunk_len], "[redacted-secret]")
            out = out.replace(trimmed[-chunk_len:], "[redacted-secret]")
    if url:
        if url in out:
            out = out.replace(url, sanitize_url(url) or "[redacted-url]")
        try:
            parts = urlsplit(url)
            fragment = parts.fragment
            if fragment and fragment in out:
                out = out.replace(fragment, "[redacted-fragment]")
                if len(fragment) > 8:
                    out = out.replace(fragment[:8], "[redacted-fragment]")
            if parts.query and parts.query in out:
                out = out.replace(parts.query, "[redacted-query]")
        except Exception:
            pass
    return out
