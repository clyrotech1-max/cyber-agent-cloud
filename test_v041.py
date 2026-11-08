"""v0.4.1 tests: web_search (DuckDuckGo HTML) + no-fabrication / language
rules in the SYSTEM prompt.

Run:  .venv/bin/python test_v041.py
Uses a throwaway DATA_DIR (/tmp/cybnet-v041-test-data) - never the real data/.
No real Gemini key is needed: the agent-runtime tests stub the LLM
(monkeypatched generate) to prove tool dispatch. A live-LLM E2E (model
choosing web_search on its own) needs the Render GEMINI_API_KEY and is
verified on the live deploy, not here.

Sandbox notes (this VM, not production):
- Local DNS returns synthetic 198.18/15 addresses for EVERY public host,
  so the strict is_global check blocks real hosts here. The LIVE search
  test therefore resolves html.duckduckgo.com via DNS-over-HTTPS
  (https://dns.google/resolve) and stubs ONLY that DNS answer with the
  true public IP; the HTTP fetch itself is real (through the sandbox
  egress proxy). On Render, real DNS is used - no stub. If DoH is
  unreachable, a known-good IP (52.149.246.39, verified 8 Nov 2026) is
  used as fallback.
- The parser and block/empty handling are also tested deterministically
  with a fake httpx client and embedded fixtures, so they do not depend
  on the network at all.
"""
import asyncio
import json
import os
import shutil
import sys
import urllib.request

DATA_DIR = "/tmp/cybnet-v041-test-data"
shutil.rmtree(DATA_DIR, ignore_errors=True)
os.environ["DATA_DIR"] = DATA_DIR
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.fetch import (  # noqa: E402
    _SearchResultsParser, web_search,
)
from app import auth as authmod  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# --- Embedded DuckDuckGo-style fixture (2 uddg links + 1 direct link) ---
DDG_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat news at DuckDuckGo</title></head><body>
<div class="results">
<div class="result results_links results_links_deep web-result">
<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.dailyhayat.net%2F&amp;rut=abc123">Daily Hayat - Latest News</a>
<a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.dailyhayat.net%2F&amp;rut=abc123">Daily Hayat ki taaza khabrain &amp; updates.</a>
</div>
<div class="result results_links results_links_deep web-result">
<a rel="nofollow" class="result__a" href="https://example.com/daily-hayat">Example Daily Hayat page</a>
</div>
<div class="result results_links results_links_deep web-result">
<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdailyhayat.net%2F&amp;rut=def456">روزنامہ حیات | Daily Hayat</a>
<a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdailyhayat.net%2F&amp;rut=def456">Muzaffarabad, Rawalakot, Mirpur ki khabrain.</a>
</div>
</div></body></html>"""

CAPTCHA_FIXTURE = """<!DOCTYPE html><html><head><title>DuckDuckGo</title></head><body>
<h1>Please verify you are human</h1>
<p>This request was filtered because it looks like an automated request. Complete the captcha to continue.</p>
</body></html>"""

EMPTY_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat zzzzz at DuckDuckGo</title></head><body>
<div class="results"><p>No more results.</p></div></body></html>"""

# Bing page with no b_algo results (used for the "both engines empty" case).
BING_EMPTY_FIXTURE = """<!DOCTYPE html><html><head><title>Daily Hayat zzzzz - Search</title></head><body>
<div id="b_content"><ol id="b_results"></ol><p>No results found.</p></div></body></html>"""


def test_parser_fixture():
    p = _SearchResultsParser()
    p.feed(DDG_FIXTURE)
    check("parser finds 3 results", len(p.results) == 3, str(len(p.results)))
    r0 = p.results[0]
    check("parser decodes uddg URL",
          r0["url"] == "https://news.dailyhayat.net/", r0["url"])
    check("parser title 1", r0["title"] == "Daily Hayat - Latest News", r0["title"])
    check("parser snippet 1 + entity decoded",
          r0["snippet"] == "Daily Hayat ki taaza khabrain & updates.", r0["snippet"])
    r1 = p.results[1]
    check("parser direct http href kept",
          r1["url"] == "https://example.com/daily-hayat", r1["url"])
    check("parser missing snippet is empty", r1["snippet"] == "", repr(r1["snippet"]))
    r2 = p.results[2]
    check("parser Urdu-script title kept",
          r2["title"] == "روزنامہ حیات | Daily Hayat", r2["title"])
    check("parser snippet 3", "Muzaffarabad" in r2["snippet"], r2["snippet"])
    p2 = _SearchResultsParser()
    p2.feed(EMPTY_FIXTURE)
    check("parser empty page -> 0 results", p2.results == [], str(p2.results))


# --- Fake httpx client (same pattern as test_v04.py) for deterministic
# web_search tests that do not touch the network. ---
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
        return _FakeStreamCtx(self._responses.pop(0))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _search_stub_resolver(host):
    """Stub BOTH search hosts (Bing primary, DDG fallback) to a public IP;
    anything else resolves for real (and will be blocked if private).
    v0.4.2: web_search tries Bing first, so fake-client tests must serve a
    Bing response before the DDG one."""
    if host in ("www.bing.com", "html.duckduckgo.com"):
        return ["93.184.216.34"]
    from app.fetch import _resolve_ips
    return _resolve_ips(host)


async def test_search_fake_client():
    import app.fetch as fetchmod
    import httpx as _httpx
    real_client = _httpx.AsyncClient
    try:
        # v0.4.2: web_search tries Bing FIRST, then DDG. Each fake sequence
        # therefore serves a Bing response first, then the DDG one. NOTE:
        # the fake client MUST be one shared instance - _fetch_raw creates
        # a new client per attempt, so a lambda returning a fresh list
        # would re-serve the Bing response to the DDG call.
        # 1) Bing fails (403) -> DDG fallback returns results.
        _fake1 = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _FakeResponse(200, {"content-type": "text/html; charset=utf-8"},
                          DDG_FIXTURE.encode()),
        ])
        _httpx.AsyncClient = lambda **kw: _fake1
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("search bing-fail + ddg fallback returns results",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        check("search fallback lists 3 results",
              r.count("URL: http") == 3, r[:300])
        check("search fallback snippet shown",
              "taaza khabrain" in r, r[:300])
        # 2) Bing fails, DDG CAPTCHA page -> plain block, no invented results.
        _fake2 = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _FakeResponse(200, {"content-type": "text/html"},
                          CAPTCHA_FIXTURE.encode()),
        ])
        _httpx.AsyncClient = lambda **kw: _fake2
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("search ddg captcha page -> SEARCH BLOCKED",
              r.startswith("SEARCH BLOCKED") and "CAPTCHA" in r, r[:160])
        # 3) Both engines return empty pages -> "no results found".
        _fake3 = _FakeClient([
            _FakeResponse(200, {"content-type": "text/html"},
                          BING_EMPTY_FIXTURE.encode()),
            _FakeResponse(200, {"content-type": "text/html"},
                          EMPTY_FIXTURE.encode()),
        ])
        _httpx.AsyncClient = lambda **kw: _fake3
        r = await web_search("Daily Hayat zzzzz", _resolver=_search_stub_resolver)
        check("search both empty -> no results found",
              r.startswith("SEARCH: no results found"), r[:160])
        # 4) Non-200 on both -> SEARCH FAILED with the status.
        _fake4 = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
        ])
        _httpx.AsyncClient = lambda **kw: _fake4
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("search both non-200 -> SEARCH FAILED",
              r.startswith("SEARCH FAILED") and "403" in r, r[:160])
        # 5) Empty query -> blocked before any fetch.
        r = await web_search("   ")
        check("search empty query blocked",
              r.startswith("SEARCH BLOCKED"), r[:100])
        # 6) Transient DDG HTTP 202 -> one retry, then results. NOTE: the
        # fake client must be ONE shared instance - _fetch_raw creates a
        # new client per attempt, so a fresh list per call would re-serve 202.
        _fake202 = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _FakeResponse(202, {"content-type": "text/html"}, b""),
            _FakeResponse(200, {"content-type": "text/html; charset=utf-8"},
                          DDG_FIXTURE.encode()),
        ])
        _httpx.AsyncClient = lambda **kw: _fake202
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("search transient 202 retried once",
              r.startswith("SEARCH: Daily Hayat news") and "news.dailyhayat.net" in r, r[:200])
        # 7) 202 twice -> reported as failure, not retried forever.
        _fake202b = _FakeClient([
            _FakeResponse(403, {"content-type": "text/html"}, b"Forbidden"),
            _FakeResponse(202, {"content-type": "text/html"}, b""),
            _FakeResponse(202, {"content-type": "text/html"}, b""),
        ])
        _httpx.AsyncClient = lambda **kw: _fake202b
        r = await web_search("Daily Hayat news", _resolver=_search_stub_resolver)
        check("search double 202 -> SEARCH FAILED",
              r.startswith("SEARCH FAILED") and "202" in r, r[:160])
    finally:
        _httpx.AsyncClient = real_client


async def test_search_ssrf():
    # DDG host resolving to a private IP must be blocked by the SSRF guard.
    def _private_resolver(host):
        return ["10.0.0.1"]

    r = await web_search("Daily Hayat news", _resolver=_private_resolver)
    check("search SSRF: private DDG IP blocked",
          r.startswith("SEARCH BLOCKED") and "10.0.0.1" in r, r[:160])


# --- Live test: real DuckDuckGo fetch through the sandbox egress proxy.
# Only the DNS answer is stubbed (real IP via DNS-over-HTTPS, fallback to
# a known-good IP); the HTTP fetch itself is real. ---
_DDG_IP_CACHE = {}


def _ddg_real_ip():
    if "ip" in _DDG_IP_CACHE:
        return _DDG_IP_CACHE["ip"]
    ip = None
    try:
        with urllib.request.urlopen(
                "https://dns.google/resolve?name=html.duckduckgo.com&type=A",
                timeout=15) as resp:
            data = json.load(resp)
        for ans in data.get("Answer", []):
            if ans.get("type") == 1 and ans.get("data"):
                ip = ans["data"]
                break
    except Exception as e:
        print(f"  [DoH lookup failed ({e}), using fallback IP]")
    if not ip:
        ip = "52.149.246.39"
    _DDG_IP_CACHE["ip"] = ip
    return ip


def _ddg_live_resolver(host):
    if host == "html.duckduckgo.com":
        return [_ddg_real_ip()]
    from app.fetch import _resolve_ips
    return _resolve_ips(host)


async def test_search_live():
    r = await web_search("Daily Hayat news", _resolver=_ddg_live_resolver)
    check("live search returns results",
          r.startswith("SEARCH: Daily Hayat news") and "URL: http" in r, r[:300])
    check("live search results mention Hayat",
          "hayat" in r.lower(), r[:300])
    check("live search returns >= 3 results",
          r.count("URL: http") >= 3, f"count={r.count('URL: http')}")


def test_system_prompt_rules():
    import app.agent.runtime as rtmod
    s = rtmod.SYSTEM
    check("SYSTEM has NO FABRICATION rule", "NO FABRICATION" in s)
    check("SYSTEM no-fabrication quotes tool output",
          "quote the tool's own words" in s)
    check("SYSTEM no-fabrication search-then-fetch flow",
          "first use web_search to find it, then fetch_url to read it" in s)
    check("SYSTEM language mirrors script (Roman Urdu in -> out)",
          "Roman Urdu (Latin letters) in -> Roman Urdu out" in s)
    check("SYSTEM never switch scripts", "Never switch scripts" in s)
    check("SYSTEM has SEARCH section", "SEARCH - FINDING A SITE" in s)
    check("SYSTEM tool list includes web_search",
          "web_search" in s and '"query": "Daily Hayat news"' in s)


async def test_runtime_wiring():
    import app.agent.runtime as rtmod
    from app.config import settings
    from app.agent.runtime import AgentRuntime

    user, _tok = authmod.register("v041-rt@example.com", "testpass123")
    uid = user["id"]

    # --- Task 1: stubbed LLM calls web_search; the real search runs
    # through the live resolver (real DuckDuckGo fetch). ---
    async def search_live(query):
        from app.fetch import web_search as real_search
        return await real_search(query, _resolver=_ddg_live_resolver)

    rtmod.web_search = search_live
    try:
        rt = AgentRuntime(settings, "s1", "daily hayat ye kaha pr ha or kya ha",
                          authed=True, user_id=uid)
        script = [
            {"plan": "search the web for Daily Hayat", "tool": "web_search",
             "args": {"query": "Daily Hayat news"}, "verify": "observation lists results"},
            {"plan": "report", "tool": "finish",
             "args": {"result": "> Daily Hayat aik news site hai.\n\n**Daily Hayat** ka pata search se mila hai."},
             "verify": "n/a"},
        ]

        async def fake_generate(prompt, timeout=20):
            step = script.pop(0)
            return json.dumps(step), "stub-model"

        rt.provider.generate = fake_generate
        out = await rt.run()
        obs = [s["observation"] for s in out["steps"]]
        check("runtime web_search dispatched + real results",
              any("SEARCH: Daily Hayat news" in o and "URL: http" in o for o in obs),
              str(obs)[:300])
        check("runtime search task completed", out["status"] == "completed", out["status"])
    finally:
        from app.fetch import web_search as real_search2
        rtmod.web_search = real_search2

    # --- Guest: web_search is login-gated like every other tool. ---
    rtg = AgentRuntime(settings, "s2", "daily hayat ye kaha pr ha", authed=False, user_id=None)

    async def fake_generate_guest(prompt, timeout=20):
        return json.dumps({"plan": "search", "tool": "web_search",
                           "args": {"query": "Daily Hayat news"}, "verify": "n/a"}), "stub-model"

    rtg.provider.generate = fake_generate_guest
    outg = await rtg.run()
    check("guest web_search blocked by login gate",
          outg["status"] == "completed" and "log in" in (outg.get("result") or "").lower(),
          str(outg.get("result"))[:120])
    authmod.delete_account(uid)


async def main():
    test_parser_fixture()
    await test_search_fake_client()
    await test_search_ssrf()
    await test_search_live()
    test_system_prompt_rules()
    await test_runtime_wiring()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL v0.4.1 TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
