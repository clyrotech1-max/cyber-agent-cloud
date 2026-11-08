"""v0.4.2 tests: web_search via Bing HTML (primary) + DuckDuckGo fallback.

Run:  .venv/bin/python test_v042.py
No real Gemini key is needed: everything here tests the search machinery
directly (parser + fake httpx client). The live-LLM E2E (model choosing
web_search on its own) is verified on the live deploy, not here.

Why Bing first (8 Nov 2026, live-verified): DuckDuckGo (html + lite)
times out from Render's datacenter IP (20s, twice), while Bing search
returns 200 from Render with real results. DDG stays as the fallback.

Sandbox notes (this VM, not production):
- Local DNS returns synthetic 198.18/15 addresses for EVERY public host,
  so the strict is_global check blocks real hosts here. The LIVE search
  test therefore resolves www.bing.com via DNS-over-HTTPS
  (https://dns.google/resolve) and stubs ONLY that DNS answer with the
  true public IP; the HTTP fetch itself is real (through the sandbox
  egress proxy). On Render, real DNS is used - no stub. If DoH is
  unreachable, or Bing blocks/times out from this sandbox, the live test
  is SKIPPED (printed, not a failure) - the live check then runs on
  Render after deploy.
- Parser and fallback behaviour are tested deterministically with a fake
  httpx client and embedded fixtures, so they do not depend on the
  network at all.
"""
import asyncio
import json
import sys
import urllib.request

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

import httpx  # noqa: E402
from app.fetch import (  # noqa: E402
    _BingResultsParser, _bing_real_url, _decode_bing_u, web_search,
)

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# --- Embedded Bing-style fixture ---
# `u` params are "a1" + base64url(target URL), exactly as Bing serves them
# (verified against the live Bing page fetched from Render 8 Nov 2026).
BING_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat news - Search</title></head><body>
<div id="b_content"><ol id="b_results">
<li class="b_algo" data-bm="1"><h2><a href="https://www.bing.com/ck/a?!&&p=abc123&amp;u=a1aHR0cHM6Ly9uZXdzLmRhaWx5aGF5YXQubmV0Lw&amp;ntb=1">Daily Hayat - Latest News</a></h2>
<div class="b_caption"><div class="b_attribution">news.dailyhayat.net</div><p class="b_lineclamp2">Daily Hayat ki taaza khabrain &amp; updates.</p></div></li>
<li class="b_algo" data-bm="2"><h2><a href="https://example.com/daily-hayat">Example Daily Hayat page</a></h2>
<div class="b_caption"><p class="b_lineclamp2">An example page about Daily Hayat.</p>
<div class="b_vlist2col"><ul><li><a href="https://example.com/related">Related link</a></li></ul></div></div></li>
<li class="b_algo" data-bm="3"><h2><a href="https://www.bing.com/ck/a?!&&p=def456&amp;u=a1aHR0cHM6Ly9kYWlseWhheWF0Lm5ldC8&amp;ntb=1">روزنامہ حیات | Daily Hayat</a></h2>
<div class="b_caption"><p>Muzaffarabad, Rawalakot, Mirpur ki khabrain.</p></div></li>
<li class="b_algo" data-bm="4"><h2><a href="https://www.bing.com/ck/a?!&&p=ghi789&amp;u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS9uby1zbmlwcGV0&amp;ntb=1">No snippet result</a></h2>
<div class="b_caption"></div></li>
</ol>
<div class="b_pag"><ul><li><a href="/search?q=Daily+Hayat+news&amp;first=11">Next</a></li></ul></div>
</div></body></html>"""

BING_CAPTCHA_FIXTURE = """<!DOCTYPE html><html><head><title>Bing</title></head><body>
<h1>Sorry</h1>
<p>Please verify you are human. This request looks like an automated request.</p>
</body></html>"""

BING_EMPTY_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat zzzzz - Search</title></head><body>
<div id="b_content"><ol id="b_results"></ol><p>No results found.</p></div></body></html>"""

# DuckDuckGo fixture (same as test_v041.py) for the fallback path.
DDG_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat news at DuckDuckGo</title></head><body>
<div class="results">
<div class="result results_links results_links_deep web-result">
<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.dailyhayat.net%2F&amp;rut=abc123">Daily Hayat - Latest News</a>
<a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.dailyhayat.net%2F&amp;rut=abc123">Daily Hayat ki taaza khabrain &amp; updates.</a>
</div>
</div></body></html>"""

DDG_EMPTY_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat zzzzz at DuckDuckGo</title></head><body>
<div class="results"><p>No more results.</p></div></body></html>"""


def test_bing_url_decode():
    check("bing u decode (a1 prefix)",
          _decode_bing_u("a1aHR0cHM6Ly9uZXdzLmRhaWx5aGF5YXQubmV0Lw") == "https://news.dailyhayat.net/")
    check("bing u decode (no prefix)",
          _decode_bing_u("aHR0cHM6Ly9uZXdzLmRhaWx5aGF5YXQubmV0Lw") == "https://news.dailyhayat.net/")
    check("bing u decode (dailyhayat.net)",
          _decode_bing_u("a1aHR0cHM6Ly9kYWlseWhheWF0Lm5ldC8") == "https://dailyhayat.net/")
    check("bing u decode garbage -> empty",
          _decode_bing_u("a1AAAA") == "", repr(_decode_bing_u("a1AAAA")))
    check("bing u decode empty -> empty", _decode_bing_u("") == "")
    check("bing real url: ck/a redirect decoded",
          _bing_real_url("https://www.bing.com/ck/a?!&&p=x&u=a1aHR0cHM6Ly9uZXdzLmRhaWx5aGF5YXQubmV0Lw&ntb=1")
          == "https://news.dailyhayat.net/")
    check("bing real url: direct https kept",
          _bing_real_url("https://example.com/daily-hayat") == "https://example.com/daily-hayat")
    check("bing real url: protocol-relative kept",
          _bing_real_url("//example.com/x") == "https://example.com/x")
    check("bing real url: javascript dropped",
          _bing_real_url("javascript:void(0)") == "")
    check("bing real url: relative path dropped",
          _bing_real_url("/search?q=x") == "")
    check("bing real url: ck/a without u dropped",
          _bing_real_url("https://www.bing.com/ck/a?!&&p=x&ntb=1") == "")


def test_bing_parser_fixture():
    p = _BingResultsParser()
    p.feed(BING_FIXTURE)
    check("bing parser finds 4 results", len(p.results) == 4, str(len(p.results)))
    r0 = p.results[0]
    check("bing parser decodes ck/a URL",
          r0["url"] == "https://news.dailyhayat.net/", r0["url"])
    check("bing parser title 1",
          r0["title"] == "Daily Hayat - Latest News", r0["title"])
    check("bing parser snippet 1 + entity decoded",
          r0["snippet"] == "Daily Hayat ki taaza khabrain & updates.", r0["snippet"])
    r1 = p.results[1]
    check("bing parser direct href kept",
          r1["url"] == "https://example.com/daily-hayat", r1["url"])
    check("bing parser nested li does not end result",
          r1["title"] == "Example Daily Hayat page" and "example page about" in r1["snippet"],
          r1["title"] + " / " + r1["snippet"])
    r2 = p.results[2]
    check("bing parser Urdu-script title kept",
          r2["title"] == "روزنامہ حیات | Daily Hayat", r2["title"])
    check("bing parser plain <p> snippet",
          "Muzaffarabad" in r2["snippet"], r2["snippet"])
    r3 = p.results[3]
    check("bing parser missing snippet is empty",
          r3["snippet"] == "" and r3["url"] == "https://example.com/no-snippet",
          repr(r3))
    check("bing parser ignores pagination li",
          all("b_pag" not in r["title"] for r in p.results))
    p2 = _BingResultsParser()
    p2.feed(BING_EMPTY_FIXTURE)
    check("bing parser empty page -> 0 results", p2.results == [], str(p2.results))
    p3 = _BingResultsParser()
    p3.feed(BING_CAPTCHA_FIXTURE)
    check("bing parser captcha page -> 0 results", p3.results == [], str(p3.results))


# --- Fake httpx client (same pattern as test_v04.py / test_v041.py).
# A response entry may also be an Exception, which stream() raises. ---
class _FakeResponse:
    def __init__(self, status, headers=None, body=b""):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    async def aiter_bytes(self, chunk_size=65536):
        if self._body:
            yield self._body


class _FakeStreamCtx:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def stream(self, method, url, headers=None):
        self.calls.append(url)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return _FakeStreamCtx(item)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _search_stub_resolver(host):
    """Stub BOTH search hosts to a public IP; anything else resolves real."""
    if host in ("www.bing.com", "html.duckduckgo.com"):
        return ["93.184.216.34"]
    from app.fetch import _resolve_ips
    return _resolve_ips(host)


def _timeout_exc(url):
    return httpx.TimeoutException("timed out", request=httpx.Request("GET", url))


def _html_resp(body):
    return _FakeResponse(200, {"content-type": "text/html; charset=utf-8"},
                         body.encode())


async def test_search_fake_client():
    real_client = httpx.AsyncClient
    try:
        # 1) Bing success -> results from Bing, DDG never called.
        fake = _FakeClient([_html_resp(BING_FIXTURE)])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("bing success returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        check("bing success lists 4 results", r.count("URL: http") == 4, r[:300])
        check("bing success snippet shown", "taaza khabrain" in r, r[:300])
        check("bing success does not call DDG",
              len(fake.calls) == 1 and "bing.com" in fake.calls[0], str(fake.calls))
        # 2) Bing 403 -> DDG fallback returns results.
        fake = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _html_resp(DDG_FIXTURE),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("bing 403 -> ddg fallback returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        check("bing 403 -> both engines called",
              len(fake.calls) == 2 and "bing.com" in fake.calls[0]
              and "duckduckgo.com" in fake.calls[1], str(fake.calls))
        # 3) Bing timeout -> DDG fallback returns results.
        fake = _FakeClient([
            _timeout_exc("https://www.bing.com/search?q=Daily+Hayat+news"),
            _html_resp(DDG_FIXTURE),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("bing timeout -> ddg fallback returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        # 4) Bing CAPTCHA page -> DDG fallback returns results.
        fake = _FakeClient([
            _html_resp(BING_CAPTCHA_FIXTURE),
            _html_resp(DDG_FIXTURE),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("bing captcha -> ddg fallback returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        # 5) Bing empty page -> DDG fallback returns results.
        fake = _FakeClient([
            _html_resp(BING_EMPTY_FIXTURE),
            _html_resp(DDG_FIXTURE),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("bing empty -> ddg fallback returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        # 6) Both time out -> honest combined failure, no invented results.
        fake = _FakeClient([
            _timeout_exc("https://www.bing.com/search?q=Daily+Hayat+news"),
            _timeout_exc("https://html.duckduckgo.com/html/?q=Daily+Hayat+news"),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("both timeout -> SEARCH FAILED, no results",
              r.startswith("SEARCH FAILED") and "URL: http" not in r
              and "Bing" in r and "DuckDuckGo" in r, r[:250])
        # 7) Both empty -> "no results found".
        fake = _FakeClient([
            _html_resp(BING_EMPTY_FIXTURE),
            _html_resp(DDG_EMPTY_FIXTURE),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat zzzzz", _resolver=_search_stub_resolver)
        check("both empty -> no results found",
              r.startswith("SEARCH: no results found") and "Bing and DuckDuckGo" in r, r[:200])
        # 8) Both non-200 -> SEARCH FAILED with both statuses.
        fake = _FakeClient([
            _FakeResponse(500, {"content-type": "text/html"}, b"Error"),
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
        ])
        httpx.AsyncClient = lambda **kw: fake
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("both non-200 -> SEARCH FAILED with statuses",
              r.startswith("SEARCH FAILED") and "500" in r and "403" in r, r[:250])
        # 9) Empty query -> blocked before any fetch.
        r = await web_search("   ")
        check("search empty query blocked",
              r.startswith("SEARCH BLOCKED"), r[:100])
    finally:
        httpx.AsyncClient = real_client


async def test_search_ssrf():
    # Both search hosts resolving to a private IP must be blocked.
    def _private_resolver(host):
        return ["10.0.0.1"]

    r = await web_search("Daily Hayat news", _resolver=_private_resolver)
    check("search SSRF: private IPs blocked on both engines",
          r.startswith("SEARCH BLOCKED") and "10.0.0.1" in r, r[:250])


# --- Live test: real Bing fetch through the sandbox egress proxy.
# Only the DNS answer is stubbed (real IP via DNS-over-HTTPS); the HTTP
# fetch itself is real. If DoH fails, or Bing blocks/times out from this
# sandbox, the test is SKIPPED (printed, not a failure) - the live check
# then runs on Render after deploy. ---
def _bing_real_ip():
    try:
        with urllib.request.urlopen(
                "https://dns.google/resolve?name=www.bing.com&type=A",
                timeout=15) as resp:
            data = json.load(resp)
        for ans in data.get("Answer", []):
            if ans.get("type") == 1 and ans.get("data"):
                return ans["data"]
    except Exception as e:
        print(f"  [DoH lookup for bing failed ({e})]")
    return None


async def test_search_live():
    ip = _bing_real_ip()
    if not ip:
        print("SKIP live Bing search: could not resolve www.bing.com via DoH "
              "(sandbox DNS lies; live check must run on Render)")
        return

    def _bing_live_resolver(host):
        if host == "www.bing.com":
            return [ip]
        from app.fetch import _resolve_ips
        return _resolve_ips(host)

    r = await web_search("Daily Hayat news", _resolver=_bing_live_resolver)
    if r.startswith("SEARCH FAILED") or r.startswith("SEARCH BLOCKED"):
        print("SKIP live Bing search: Bing did not answer from this sandbox "
              f"({r[:200]}) - live check must run on Render")
        return
    check("live Bing search returns results",
          r.startswith("SEARCH: Daily Hayat news") and "URL: http" in r, r[:300])
    check("live Bing search results mention Hayat",
          "hayat" in r.lower(), r[:300])
    check("live Bing search returns >= 3 results",
          r.count("URL: http") >= 3, f"count={r.count('URL: http')}")


async def main():
    test_bing_url_decode()
    test_bing_parser_fixture()
    await test_search_fake_client()
    await test_search_ssrf()
    await test_search_live()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL v0.4.2 TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
