"""SSRF-safe read-only web fetch (the agent's `fetch_url` tool) and
web search (the agent's `web_search` tool, via DuckDuckGo HTML).

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
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

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

# Web search (v0.4.1): DuckDuckGo HTML endpoint. A browser-like UA is used
# because the html endpoint serves results pages to browsers; it is not a
# block bypass - if DDG answers with a CAPTCHA/block page, web_search
# reports that plainly and never invents results.
SEARCH_UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
             "Accept": "text/html,*/*"}
SEARCH_MAX_RESULTS = 8
SEARCH_SNIPPET_CHARS = 300


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


async def _fetch_raw(url: str, _resolver=None, headers=None):
    """Low-level SSRF-safe GET shared by fetch_url and web_search.

    Returns a dict:
      ok=True  -> {"ok": True, "url": final_url, "status": int,
                   "content_type": str, "body": bytes, "truncated": bool}
      ok=False -> {"ok": False, "message": "FETCH BLOCKED: ..." |
                   "FETCH FAILED: ..." | "FETCH: ... (no Location header)"}
    Every request (initial + each redirect hop) is validated the same way:
    the hostname is resolved and EVERY A/AAAA address must be globally
    routable. 20s timeout per request, 200KB body cap.
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "message": "FETCH BLOCKED: no URL given."}
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "message": (
            f"FETCH BLOCKED: only http/https URLs are allowed, "
            f"got scheme {parsed.scheme or '(none)'} - give a full URL like https://example.com.")}
    if not parsed.hostname:
        return {"ok": False, "message": "FETCH BLOCKED: URL has no host."}
    if parsed.username or parsed.password:
        return {"ok": False, "message": "FETCH BLOCKED: URLs with embedded credentials are not allowed."}
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
                return {"ok": False, "message": f"FETCH BLOCKED: {e}"}
            try:
                async with client.stream("GET", current, headers=headers or UA) as r:
                    status = r.status_code
                    if status in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location")
                        if not loc:
                            return {"ok": False, "message": (
                                f"FETCH: {current} returned HTTP {status} "
                                f"with no Location header.")}
                        hops += 1
                        if hops > MAX_REDIRECTS:
                            return {"ok": False, "message": (
                                f"FETCH BLOCKED: too many redirects "
                                f"(>{MAX_REDIRECTS}) from {url}.")}
                        nxt = urljoin(current, loc)
                        np = urlparse(nxt)
                        if np.scheme not in ("http", "https"):
                            return {"ok": False, "message": (
                                f"FETCH BLOCKED: redirect to non-http(s) "
                                f"URL: {nxt}")}
                        if np.username or np.password:
                            return {"ok": False, "message": (
                                "FETCH BLOCKED: redirect to a URL with "
                                "embedded credentials.")}
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
                    return {"ok": True, "url": current, "status": status,
                            "content_type": r.headers.get("content-type", ""),
                            "body": bytes(body), "truncated": truncated}
            except httpx.TimeoutException:
                return {"ok": False, "message": (
                    f"FETCH FAILED: timed out after {REQUEST_TIMEOUT}s "
                    f"fetching {current}.")}
            except httpx.HTTPError as e:
                return {"ok": False, "message": f"FETCH FAILED: {type(e).__name__}: {str(e)[:200]}"}


async def fetch_url(url: str, _resolver=None) -> str:
    """Fetch a public URL read-only, SSRF-safe. Returns a formatted string.

    `_resolver` is a test-only seam (defaults to socket.getaddrinfo): it
    supplies the DNS answers so the validation can be exercised where the
    local resolver lies (this sandbox's DNS returns synthetic 198.18/15
    addresses for every public host). Production always uses real DNS.
    """
    raw = await _fetch_raw(url, _resolver=_resolver)
    if not raw["ok"]:
        return raw["message"]
    ct = raw["content_type"]
    title, text = _readable_text(ct, raw["body"])
    note = ""
    if raw["truncated"]:
        note += (f"\n[NOTE: response truncated at "
                 f"{MAX_BODY_BYTES // 1000}KB size cap]")
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        note += (f"\n[NOTE: text truncated at "
                 f"{MAX_TEXT_CHARS} characters]")
    out = (f"URL: {raw['url']}\nStatus: {raw['status']}\n"
           f"Content-Type: {ct or '(none)'}\n")
    if title:
        out += f"Title: {title}\n"
    return out + f"Content:\n{text}{note}"


# --- DuckDuckGo HTML search results parsing (stdlib html.parser only) ---
class _SearchResultsParser(HTMLParser):
    """Parses DuckDuckGo HTML results: title links (class result__a) and
    snippets (class result__snippet). Result URLs come from the `uddg`
    parameter of DDG's /l/ redirect links; plain http(s) hrefs are used
    as-is. A snippet attaches to the most recent result that has none."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []  # list of dicts {title, url, snippet}
        self._cur = None
        self._capture = None  # "title" | "snippet" | None
        self._buf = []

    def _real_url(self, href):
        href = _html.unescape((href or "").strip())
        if not href:
            return ""
        if href.startswith("//"):
            href = "https:" + href
        p = urlparse(href)
        if "duckduckgo.com" in (p.netloc or "") and p.path.startswith("/l/"):
            uddg = parse_qs(p.query).get("uddg", [None])[0]
            return (uddg or "").strip()
        if p.scheme in ("http", "https"):
            return href
        return ""

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        d = dict(attrs)
        cls = d.get("class", "")
        if "result__a" in cls:
            url = self._real_url(d.get("href", ""))
            if url:
                self._cur = {"title": "", "url": url, "snippet": ""}
                self.results.append(self._cur)
                self._capture = "title"
                self._buf = []
        elif "result__snippet" in cls and self._cur is not None and not self._cur["snippet"]:
            self._capture = "snippet"
            self._buf = []

    def handle_endtag(self, tag):
        if tag != "a" or self._capture is None:
            return
        text = " ".join("".join(self._buf).split())
        if self._capture == "title" and self._cur is not None:
            self._cur["title"] = text
        elif self._capture == "snippet" and self._cur is not None:
            self._cur["snippet"] = text
        self._capture = None
        self._buf = []

    def handle_data(self, data):
        if self._capture is not None:
            self._buf.append(data)


# Markers of a DDG block/CAPTCHA page. Only treated as a block when the
# page also yields ZERO results (a legit snippet may mention "captcha").
_BLOCK_MARKERS = ("captcha", "unusual traffic", "automated requests",
                  "anomaly", "request was filtered")


async def web_search(query: str, _resolver=None) -> str:
    """Search the public web via DuckDuckGo HTML. Returns the top ~8
    results as title + URL + snippet.

    Reuses the same SSRF-safe machinery as fetch_url (html.duckduckgo.com
    is validated as a public host, 20s timeout, size caps). No cookies,
    no credentials. If the search page blocks us or returns nothing, that
    fact is returned plainly - results are never invented.
    """
    q = (query or "").strip()
    if not q:
        return "SEARCH BLOCKED: no query given."
    url = "https://html.duckduckgo.com/html/?q=" + quote_plus(q)
    # DDG's edge occasionally answers HTTP 202 ("accepted, not ready") as a
    # transient - one retry after a short pause. This is not a CAPTCHA or a
    # block: a real block page is still reported plainly below, and a second
    # 202 is reported as a failure, not retried again.
    raw = None
    for attempt in range(2):
        raw = await _fetch_raw(url, _resolver=_resolver, headers=SEARCH_UA)
        if raw["ok"] and raw["status"] == 202 and attempt == 0:
            await asyncio.sleep(2)
            continue
        break
    if not raw["ok"]:
        msg = raw["message"]
        if msg.startswith("FETCH BLOCKED:"):
            return "SEARCH BLOCKED: " + msg[len("FETCH BLOCKED:"):].strip()
        if msg.startswith("FETCH FAILED:"):
            return "SEARCH FAILED: " + msg[len("FETCH FAILED:"):].strip()
        return "SEARCH FAILED: " + msg
    if raw["status"] != 200:
        return f"SEARCH FAILED: DuckDuckGo returned HTTP {raw['status']} for the search page."
    try:
        text = raw["body"].decode("utf-8")
    except UnicodeDecodeError:
        text = raw["body"].decode("utf-8", "replace")
    parser = _SearchResultsParser()
    parser.feed(text)
    results = [r for r in parser.results if r["title"] and r["url"]][:SEARCH_MAX_RESULTS]
    if not results:
        low = text.lower()
        if any(m in low for m in _BLOCK_MARKERS):
            return ("SEARCH BLOCKED: DuckDuckGo showed a CAPTCHA/block page instead of results "
                    f"for '{q}' - do not retry, do not invent results.")
        return ("SEARCH: no results found for '" + q + "' - the search page returned no result "
                "entries. Ask the user for the link or try a different query; do not invent results.")
    lines = [f"SEARCH: {q}"]
    for i, r in enumerate(results, 1):
        snip = r["snippet"]
        if len(snip) > SEARCH_SNIPPET_CHARS:
            snip = snip[:SEARCH_SNIPPET_CHARS] + "..."
        lines.append(f"{i}. {r['title']}\n   URL: {r['url']}")
        if snip:
            lines.append(f"   Snippet: {snip}")
    return "\n".join(lines)
