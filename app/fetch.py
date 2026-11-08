"""SSRF-safe read-only web fetch (the agent's `fetch_url` tool) and
web search (the agent's `web_search` tool).

Search engine order (v0.4.2): Bing HTML is primary, DuckDuckGo HTML is
the fallback. Reason: DuckDuckGo (html.duckduckgo.com and
lite.duckduckgo.com) times out from Render's datacenter IP (20s, twice,
live-verified 8 Nov 2026), while Bing search returns 200 from Render
with real results. If Bing fails (non-200 / timeout / CAPTCHA / zero
results), DuckDuckGo is tried once; if both fail, that fact is reported
plainly - results are never invented.

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
import base64
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

# Web search (v0.4.1/v0.4.2): Bing HTML is primary, DuckDuckGo HTML the
# fallback. A browser-like UA is used because both endpoints serve results
# pages to browsers; it is not a block bypass - if either answers with a
# CAPTCHA/block page, web_search reports that plainly and never invents
# results.
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


# --- Bing HTML search results parsing (stdlib html.parser only) ---
def _decode_bing_u(u):
    """Decode a Bing /ck/a redirect `u` parameter to the real target URL.

    Bing prefixes the base64url-encoded target with "a1" (a version
    marker), so the whole value does not decode to a URL - try it whole
    first, then with the 2-char prefix stripped. Returns "" when neither
    decodes to an http(s) URL.
    """
    for cand in (u, u[2:]):
        s = cand.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        try:
            dec = base64.b64decode(s).decode("utf-8", "replace").strip()
        except Exception:
            continue
        if dec.startswith("http://") or dec.startswith("https://"):
            return dec
    return ""


def _bing_real_url(href):
    """Recover the real target URL from a Bing result link."""
    href = _html.unescape((href or "").strip())
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    p = urlparse(href)
    if "bing.com" in (p.netloc or "") and p.path.startswith("/ck/a"):
        u = parse_qs(p.query).get("u", [None])[0]
        if u:
            return _decode_bing_u(u)
        return ""
    if p.scheme in ("http", "https"):
        return href
    return ""


class _BingResultsParser(HTMLParser):
    """Parses Bing search results: <li class="b_algo"> blocks with an
    <h2><a> title link and a <p> snippet (first paragraph in the block).
    Result links are Bing /ck/a redirects (decoded via _bing_real_url);
    plain http(s) hrefs are used as-is. Pagination / chrome <li> blocks
    (e.g. class b_pag) are ignored - only b_algo blocks count."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []  # list of dicts {title, url, snippet}
        self._in_algo = False
        self._li_depth = 0
        self._cur = None
        self._capture = None  # "title" | "snippet" | None
        self._buf = []
        self._in_h2 = False
        self._got_snippet = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "li":
            if not self._in_algo and "b_algo" in d.get("class", "").split():
                self._in_algo = True
                self._li_depth = 1
                self._cur = {"title": "", "url": "", "snippet": ""}
                self._capture = None
                self._got_snippet = False
            elif self._in_algo:
                self._li_depth += 1
            return
        if not self._in_algo or self._cur is None:
            return
        if tag == "h2":
            self._in_h2 = True
        elif tag == "a" and self._in_h2 and not self._cur["url"]:
            url = _bing_real_url(d.get("href", ""))
            if url:
                self._cur["url"] = url
                self._capture = "title"
                self._buf = []
        elif tag == "p" and not self._got_snippet and self._capture != "title":
            self._capture = "snippet"
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "li" and self._in_algo:
            self._li_depth -= 1
            if self._li_depth == 0:
                if self._cur is not None and self._cur["title"] and self._cur["url"]:
                    self.results.append(self._cur)
                self._in_algo = False
                self._cur = None
                self._capture = None
            return
        if not self._in_algo or self._cur is None:
            return
        if tag == "h2":
            self._in_h2 = False
        elif tag == "a" and self._capture == "title":
            self._cur["title"] = " ".join("".join(self._buf).split())
            self._capture = None
            self._buf = []
        elif tag == "p" and self._capture == "snippet":
            self._cur["snippet"] = " ".join("".join(self._buf).split())
            self._got_snippet = True
            self._capture = None
            self._buf = []

    def handle_data(self, data):
        if self._in_algo and self._capture is not None:
            self._buf.append(data)


# Markers of a search-engine block/CAPTCHA page. Only treated as a block
# when the page also yields ZERO results (a legit snippet may mention
# "captcha").
_BLOCK_MARKERS = ("captcha", "unusual traffic", "automated requests",
                  "anomaly", "request was filtered", "verify you are human",
                  "not a robot")


def _fetch_error_short(msg):
    """Shorten a _fetch_raw failure message for the combined search error."""
    if msg.startswith("FETCH BLOCKED:"):
        return "blocked: " + msg[len("FETCH BLOCKED:"):].strip()
    if msg.startswith("FETCH FAILED:"):
        return msg[len("FETCH FAILED:"):].strip()
    return msg


def _decode_search_body(raw):
    try:
        return raw["body"].decode("utf-8")
    except UnicodeDecodeError:
        return raw["body"].decode("utf-8", "replace")


async def _search_bing(query, _resolver=None):
    """Bing HTML search. Returns (results, error): results is a list of
    {title, url, snippet} (possibly empty); error is a string or None."""
    url = "https://www.bing.com/search?q=" + quote_plus(query)
    raw = await _fetch_raw(url, _resolver=_resolver, headers=SEARCH_UA)
    if not raw["ok"]:
        return [], "Bing " + _fetch_error_short(raw["message"])
    if raw["status"] != 200:
        return [], f"Bing returned HTTP {raw['status']} for the search page."
    text = _decode_search_body(raw)
    parser = _BingResultsParser()
    parser.feed(text)
    results = [r for r in parser.results if r["title"] and r["url"]][:SEARCH_MAX_RESULTS]
    if not results:
        low = text.lower()
        if any(m in low for m in _BLOCK_MARKERS):
            return [], "Bing showed a CAPTCHA/block page instead of results"
        return [], "Bing returned no result entries"
    return results, None


async def _search_ddg(query, _resolver=None):
    """DuckDuckGo HTML search (fallback). Returns (results, error)."""
    url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
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
        return [], "DuckDuckGo " + _fetch_error_short(raw["message"])
    if raw["status"] != 200:
        return [], f"DuckDuckGo returned HTTP {raw['status']} for the search page."
    text = _decode_search_body(raw)
    parser = _SearchResultsParser()
    parser.feed(text)
    results = [r for r in parser.results if r["title"] and r["url"]][:SEARCH_MAX_RESULTS]
    if not results:
        low = text.lower()
        if any(m in low for m in _BLOCK_MARKERS):
            return [], "DuckDuckGo showed a CAPTCHA/block page instead of results"
        return [], "DuckDuckGo returned no result entries"
    return results, None


async def web_search(query: str, _resolver=None) -> str:
    """Search the public web: Bing HTML first, DuckDuckGo HTML as fallback.
    Returns the top ~8 results as title + URL + snippet.

    Reuses the same SSRF-safe machinery as fetch_url (each search host is
    validated as public, 20s timeout, size caps). No cookies, no
    credentials. If both engines fail or return nothing, that fact is
    returned plainly - results are never invented.
    """
    q = (query or "").strip()
    if not q:
        return "SEARCH BLOCKED: no query given."
    results, err_bing = await _search_bing(q, _resolver)
    if not results:
        results, err_ddg = await _search_ddg(q, _resolver)
    if results:
        lines = [f"SEARCH: {q}"]
        for i, r in enumerate(results, 1):
            snip = r["snippet"]
            if len(snip) > SEARCH_SNIPPET_CHARS:
                snip = snip[:SEARCH_SNIPPET_CHARS] + "..."
            lines.append(f"{i}. {r['title']}\n   URL: {r['url']}")
            if snip:
                lines.append(f"   Snippet: {snip}")
        return "\n".join(lines)
    if (err_bing == "Bing returned no result entries"
            and err_ddg == "DuckDuckGo returned no result entries"):
        return ("SEARCH: no results found for '" + q + "' - Bing and DuckDuckGo both "
                "returned no result entries. Ask the user for the link or try a different "
                "query; do not invent results.")
    combined = err_bing + ". DuckDuckGo fallback: " + err_ddg + "."
    prefix = "SEARCH BLOCKED" if ("CAPTCHA" in combined or "blocked" in combined.lower()) else "SEARCH FAILED"
    return (f"{prefix}: {combined} Ask the user for the link or try a different "
            "query; do not invent results.")
