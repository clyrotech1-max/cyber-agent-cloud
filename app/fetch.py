"""SSRF-safe read-only web fetch (the agent's `fetch_url` tool).

Reads any PUBLIC web page or JSON API with a plain GET. Security rules:
- Only http/https, no credentials in the URL, no cookies sent.
- Before EVERY request (including each redirect hop) the hostname is
  resolved and EVERY A/AAAA address must be globally routable
  (`ipaddress.is_global`). Private / loopback / link-local / reserved
  ranges (10/8, 127/8, 169.254.169.254, 172.16/12, 192.168/16, ::1,
  fc00::/7, 100.64/10, 198.18/15, ...) are rejected BEFORE any request.
- Max 3 redirects, each hop re-validated the same way.
- 20s timeout per request, 200KB body cap (truncate + note).
- HTTP client mirrors app/scan.py: explicit proxy from env with
  trust_env=False (the sandbox NO_PROXY contains a malformed "[::1]"
  entry that crashes httpx's env parsing), and TLS verified with
  ssl.create_default_context() so the sandbox egress CA (SSL_CERT_FILE)
  is honoured while Render uses its normal system CA bundle. Certs are
  still verified everywhere - nothing is ever fetched with verify=False.

Residual note (honest): validation happens immediately before each
request, but httpx re-resolves the hostname at connect time, so a
DNS-rebinding race (public IP at validation, private IP at connect)
is not closed by this check alone. No credentials are ever sent, so a
rebinding hit could only return a response body, never steal a secret.
Closing that race needs IP pinning in a custom transport (future work).

HTML -> readable text uses stdlib html.parser only (no beautifulsoup4):
scripts, styles, nav, noscript and svg are stripped; headings,
paragraphs, list items and links (text + href) are kept.
"""
import asyncio
import html as _html  # noqa: F401  (kept for clarity; parser unescapes)
import ipaddress
import json
import os
import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

MAX_BODY_BYTES = 200_000      # raw download cap
MAX_TEXT_CHARS = 8000         # readable-text cap in the tool result
REQUEST_TIMEOUT = 20.0        # seconds per request
MAX_REDIRECTS = 3

# Proxy explicitly from env (never logged). trust_env=False avoids httpx
# choking on malformed NO_PROXY entries like "[::1]". On Render there is
# no proxy env, so this is None and httpx connects directly.
_PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or None

UA = {"User-Agent": "CybnetAI-Cloud/0.4 (read-only-fetch)",
      "Accept": "text/html,application/json,*/*"}


class FetchBlocked(Exception):
    """Raised when a URL fails the SSRF / scheme checks."""


def _resolve_ips(host):
    """All A/AAAA addresses for host (literal IPs pass through)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _is_public(ip_str):
    """True only for a globally routable address (IPv4-mapped IPv6 unwrapped)."""
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


async def _validate_host(host, resolver=None):
    """SSRF check: every resolved IP must be globally routable."""
    if not host:
        raise FetchBlocked("URL has no host")
    resolve = resolver or _resolve_ips
    try:
        ips = await asyncio.to_thread(resolve, host)
    except Exception as e:
        raise FetchBlocked(f"could not resolve {host}: {e}")
    if not ips:
        raise FetchBlocked(f"could not resolve {host}")
    bad = [ip for ip in ips if not _is_public(ip)]
    if bad:
        raise FetchBlocked(
            f"host {host} resolves to non-public address(es): {', '.join(bad)} - blocked (SSRF guard)")
    return ips


# --- HTML -> readable text (stdlib html.parser only) ---
_SKIP_TAGS = {"script", "style", "nav", "noscript", "svg"}
_BLOCK_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "div",
               "section", "article", "tr", "blockquote", "pre", "ul", "ol"}


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self._skip_depth = 0
        self._parts = []
        self._link_href = None
        self._link_text = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "title":
            self._in_title = True
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")
        elif tag == "br":
            self._parts.append("\n")
        elif tag == "a":
            href = dict(attrs).get("href")
            self._link_href = href.strip() if href else None
            self._link_text = []

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return
        if tag == "title":
            self._in_title = False
        elif tag == "a" and self._link_href is not None:
            text = "".join(self._link_text).strip()
            if text:
                self._parts.append(f"{text} ({self._link_href})")
            self._link_href = None
            self._link_text = []
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        if self._link_href is not None:
            self._link_text.append(data)
            return
        self._parts.append(data)

    def text(self):
        raw = "".join(self._parts)
        lines = [re.sub(r"\s+", " ", ln).strip() for ln in raw.split("\n")]
        return "\n".join(ln for ln in lines if ln)


def _readable_text(content_type, body: bytes):
    """Return (title, text) for a response body."""
    ct = (content_type or "").lower()
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        decoded = body.decode("utf-8", "replace")
    # JSON: by content-type, or by shape as a fallback.
    if "json" in ct or decoded.strip()[:1] in ("{", "["):
        try:
            obj = json.loads(decoded)
            return "", "JSON:\n" + json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception:
            pass
    # HTML (by content-type or sniffing) -> extracted text + title.
    head = decoded[:2000].lower()
    if "text/html" in ct or "<html" in head or "<!doctype html" in head:
        ex = _TextExtractor()
        ex.feed(decoded)
        return ex.title.strip(), ex.text()
    return "", decoded


async def fetch_url(url: str, _resolver=None) -> str:
    """Fetch a public URL read-only, SSRF-safe. Returns a formatted string.

    `_resolver` is a test-only seam (defaults to socket.getaddrinfo): it
    supplies the DNS answers so the validation can be exercised where the
    local resolver lies (this sandbox's DNS returns synthetic 198.18/15
    addresses for every public host). Production always uses real DNS.
    """
    url = (url or "").strip()
    if not url:
        return "FETCH BLOCKED: no URL given."
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return (f"FETCH BLOCKED: only http/https URLs are allowed, "
                f"got scheme {parsed.scheme or '(none)'} - give a full URL like https://example.com.")
    if not parsed.hostname:
        return "FETCH BLOCKED: URL has no host."
    if parsed.username or parsed.password:
        return "FETCH BLOCKED: URLs with embedded credentials are not allowed."
    ctx = ssl.create_default_context()
    hops = 0
    current = url
    async with httpx.AsyncClient(trust_env=False, proxy=_PROXY, verify=ctx,
                                 follow_redirects=False, timeout=REQUEST_TIMEOUT) as client:
        while True:
            p = urlparse(current)
            try:
                await _validate_host(p.hostname, resolver=_resolver)
            except FetchBlocked as e:
                return f"FETCH BLOCKED: {e}"
            try:
                async with client.stream("GET", current, headers=UA) as r:
                    status = r.status_code
                    if status in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location")
                        if not loc:
                            return (f"FETCH: {current} returned HTTP {status} "
                                    f"with no Location header.")
                        hops += 1
                        if hops > MAX_REDIRECTS:
                            return (f"FETCH BLOCKED: too many redirects "
                                    f"(>{MAX_REDIRECTS}) from {url}.")
                        nxt = urljoin(current, loc)
                        np = urlparse(nxt)
                        if np.scheme not in ("http", "https"):
                            return (f"FETCH BLOCKED: redirect to non-http(s) "
                                    f"URL: {nxt}")
                        if np.username or np.password:
                            return ("FETCH BLOCKED: redirect to a URL with "
                                    "embedded credentials.")
                        current = nxt
                        continue
                    body = bytearray()
                    truncated = False
                    async for chunk in r.aiter_bytes(65536):
                        body += chunk
                        if len(body) > MAX_BODY_BYTES:
                            body = body[:MAX_BODY_BYTES]
                            truncated = True
                            break
                    ct = r.headers.get("content-type", "")
                    title, text = _readable_text(ct, bytes(body))
                    note = ""
                    if truncated:
                        note += (f"\n[NOTE: response truncated at "
                                 f"{MAX_BODY_BYTES // 1000}KB size cap]")
                    if len(text) > MAX_TEXT_CHARS:
                        text = text[:MAX_TEXT_CHARS]
                        note += (f"\n[NOTE: text truncated at "
                                 f"{MAX_TEXT_CHARS} characters]")
                    out = (f"URL: {current}\nStatus: {status}\n"
                           f"Content-Type: {ct or '(none)'}\n")
                    if title:
                        out += f"Title: {title}\n"
                    return out + f"Content:\n{text}{note}"
            except httpx.TimeoutException:
                return (f"FETCH FAILED: timed out after {REQUEST_TIMEOUT}s "
                        f"fetching {current}.")
            except httpx.HTTPError as e:
                return f"FETCH FAILED: {type(e).__name__}: {str(e)[:200]}"
