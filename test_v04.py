"""v0.4 tests: SSRF-safe fetch_url + per-user memory.

Run:  .venv/bin/python test_v04.py
Uses a throwaway DATA_DIR (/tmp/cybnet-v04-test-data) - never the real data/.
No real Gemini key is needed: the agent-runtime tests stub the LLM
(monkeypatched generate) to prove tool dispatch + memory injection.
A live-LLM E2E (model choosing fetch_url/remember on its own) needs the
Render GEMINI_API_KEY and is verified on the live deploy, not here.

Sandbox notes (this VM, not production):
- Local DNS returns synthetic 198.18/15 addresses for EVERY public host,
  so the strict is_global check blocks real hosts here. The success-path
  fetch test therefore stubs ONLY the DNS answer for example.com with its
  true public IP (93.184.216.34); the HTTP fetch itself is real (through
  the sandbox egress proxy). On Render, real DNS is used - no stub.
- A live redirect chain to a blocked target cannot be exercised here
  (no public redirector is reachable with real DNS, and localhost servers
  are correctly blocked); redirect re-validation is therefore tested with
  a fake httpx client (allowed redirect followed, redirect to a private
  IP blocked, 4th redirect refused, non-http redirect refused).
"""
import asyncio
import json
import os
import shutil
import sys

DATA_DIR = "/tmp/cybnet-v04-test-data"
shutil.rmtree(DATA_DIR, ignore_errors=True)
os.environ["DATA_DIR"] = DATA_DIR
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.fetch import (  # noqa: E402
    FetchBlocked, _readable_text, _validate_host, fetch_url,
)
from app import auth as authmod  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# --- stub resolver: real public IP for example.com only, real DNS else ---
def _stub_resolver(host):
    if host == "example.com":
        return ["93.184.216.34"]
    from app.fetch import _resolve_ips
    return _resolve_ips(host)


async def test_fetch_ssrf_blocks():
    blocked_urls = [
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://10.1.2.3/admin",
        "http://192.168.1.1/",
        "http://172.16.0.5/",
        "http://localhost:8000/",
        "http://[::1]/",
        "https://10.0.0.1/",
    ]
    for u in blocked_urls:
        r = await fetch_url(u)
        check(f"SSRF block {u}", r.startswith("FETCH BLOCKED"), r[:110])
    # Non-http schemes and embedded credentials are blocked before any fetch.
    r = await fetch_url("ftp://example.com/file.txt")
    check("scheme ftp blocked", r.startswith("FETCH BLOCKED"), r[:100])
    r = await fetch_url("http://user:pass@example.com/")
    check("credentials URL blocked", r.startswith("FETCH BLOCKED"), r[:100])
    r = await fetch_url("")
    check("empty URL blocked", r.startswith("FETCH BLOCKED"), r[:100])
    r = await fetch_url("example.com")
    check("bare host (no scheme) blocked", r.startswith("FETCH BLOCKED"), r[:100])


async def test_validate_host():
    try:
        await _validate_host("10.0.0.1")
        check("validate 10.0.0.1 raises", False, "not blocked")
    except FetchBlocked as e:
        check("validate 10.0.0.1 raises", True, str(e)[:80])
    try:
        await _validate_host("localhost")
        check("validate localhost raises", False, "not blocked")
    except FetchBlocked as e:
        check("validate localhost raises", True, str(e)[:80])
    ips = await _validate_host("example.com", resolver=_stub_resolver)
    check("validate example.com (stub) allows", ips == ["93.184.216.34"], str(ips))


def test_html_extraction():
    sample = """<!doctype html><html><head><title>Test Page</title>
    <style>body { color: red; }</style><script>var x = 1;</script></head>
    <body><nav><a href="/home">Home</a><a href="/about">About</a></nav>
    <h1>Main Heading</h1><p>First paragraph with <a href="https://example.com/docs">docs link</a> inside.</p>
    <p>Second paragraph.</p><ul><li>Item one</li><li>Item two</li></ul>
    <script>alert('evil');</script></body></html>"""
    title, text = _readable_text("text/html; charset=utf-8", sample.encode())
    check("html title extracted", title == "Test Page", title)
    check("html script stripped", "alert('evil')" not in text and "var x = 1" not in text, text[:120])
    check("html style stripped", "color: red" not in text, text[:120])
    check("html nav stripped", "Home" not in text and "About" not in text, text[:120])
    check("html heading kept", "Main Heading" in text, text[:120])
    check("html paragraphs kept", "First paragraph" in text and "Second paragraph" in text, text[:120])
    check("html list kept", "Item one" in text and "Item two" in text, text[:120])
    check("html link kept with href", "docs link (https://example.com/docs)" in text, text[:200])


def test_json_pretty():
    body = json.dumps({"ok": True, "items": [1, 2, 3], "nested": {"a": "b"}}).encode()
    title, text = _readable_text("application/json", body)
    check("json pretty-printed", text.startswith("JSON:\n{") and '"ok": true' in text, text[:100])
    # JSON by shape even without a json content-type.
    title2, text2 = _readable_text("text/plain", body)
    check("json by shape fallback", text2.startswith("JSON:\n{"), text2[:60])


async def test_fetch_success():
    r = await fetch_url("https://example.com", _resolver=_stub_resolver)
    check("fetch example.com 200", "Status: 200" in r, r[:120].replace("\n", " | "))
    check("fetch example.com title", "Title: Example Domain" in r, r[:160].replace("\n", " | "))
    check("fetch example.com text", "Example Domain" in r and "documentation examples" in r.lower(),
          r[:300].replace("\n", " | "))


# --- Redirect loop tested with a fake httpx client (deterministic, no
# network): allowed redirect is followed, redirect to a private IP is
# blocked by re-validation, and a 4th redirect is refused. ---
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


async def test_redirect_logic():
    import app.fetch as fetchmod
    import httpx as _httpx
    real_client = _httpx.AsyncClient
    html200 = _FakeResponse(200, {"content-type": "text/html"},
                            b"<html><head><title>Final</title></head><body><p>Arrived.</p></body></html>")
    try:
        # 1) 301 to an allowed host is followed and re-validated.
        _httpx.AsyncClient = lambda **kw: _FakeClient([
            _FakeResponse(301, {"location": "https://example.com/"}),
            html200,
        ])
        r = await fetch_url("https://example.com/start", _resolver=_stub_resolver)
        check("redirect to allowed host followed",
              "Status: 200" in r and "Title: Final" in r and "Arrived." in r, r[:160].replace("\n", " | "))
        # 2) 302 to a private IP is blocked by re-validation (never fetched).
        _httpx.AsyncClient = lambda **kw: _FakeClient([
            _FakeResponse(302, {"location": "http://10.0.0.1/secret"}),
            html200,
        ])
        r = await fetch_url("https://example.com/start", _resolver=_stub_resolver)
        check("redirect to private IP blocked",
              r.startswith("FETCH BLOCKED") and "10.0.0.1" in r, r[:160])
        # 3) A 4th redirect is refused.
        _httpx.AsyncClient = lambda **kw: _FakeClient([
            _FakeResponse(301, {"location": "https://example.com/loop"}) for _ in range(4)
        ])
        r = await fetch_url("https://example.com/start", _resolver=_stub_resolver)
        check("too many redirects refused",
              r.startswith("FETCH BLOCKED") and "too many redirects" in r, r[:160])
        # 4) Redirect to a non-http(s) scheme is refused.
        _httpx.AsyncClient = lambda **kw: _FakeClient([
            _FakeResponse(301, {"location": "ftp://example.com/file"}),
            html200,
        ])
        r = await fetch_url("https://example.com/start", _resolver=_stub_resolver)
        check("redirect to ftp refused",
              r.startswith("FETCH BLOCKED") and "non-http" in r, r[:160])
    finally:
        _httpx.AsyncClient = real_client


def test_memory_endpoints():
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    # Unauthed -> 401 on all three endpoints.
    check("memories GET 401 logged out", c.get("/user/memories").status_code == 401)
    check("memories POST 401 logged out",
          c.post("/user/memories", json={"fact": "x"}).status_code == 401)
    check("memories DELETE 401 logged out",
          c.delete("/user/memories/abc").status_code == 401)
    # Throwaway user A.
    ra = c.post("/auth/register", json={"email": "v04-a@example.com", "password": "testpass123"})
    check("register user A", ra.status_code == 200, str(ra.status_code))
    ta = ra.json()["token"]
    ha = {"Authorization": f"Bearer {ta}"}
    rb = c.post("/auth/register", json={"email": "v04-b@example.com", "password": "testpass123"})
    tb = rb.json()["token"]
    hb = {"Authorization": f"Bearer {tb}"}
    # Empty fact -> 400.
    check("add empty fact 400",
          c.post("/user/memories", json={"fact": "  "}, headers=ha).status_code == 400)
    m1 = c.post("/user/memories", json={"fact": "User's favourite editor is VS Code"}, headers=ha)
    check("add fact A1", m1.status_code == 200 and m1.json()["memory"]["fact"].endswith("VS Code"),
          str(m1.status_code))
    m2 = c.post("/user/memories", json={"fact": "User speaks Roman Urdu"}, headers=ha)
    check("add fact A2", m2.status_code == 200, str(m2.status_code))
    lst = c.get("/user/memories", headers=ha)
    facts = [m["fact"] for m in lst.json()["memories"]]
    check("list newest first", facts == ["User speaks Roman Urdu", "User's favourite editor is VS Code"],
          str(facts))
    # Cross-user isolation: B cannot delete A's memory, and B's list is empty.
    mid_a1 = m1.json()["memory"]["id"]
    check("B cannot delete A's memory",
          c.delete(f"/user/memories/{mid_a1}", headers=hb).status_code == 404)
    check("B list empty", c.get("/user/memories", headers=hb).json()["memories"] == [])
    # A deletes one fact; the other stays.
    check("A deletes fact", c.delete(f"/user/memories/{mid_a1}", headers=ha).status_code == 200)
    left = [m["fact"] for m in c.get("/user/memories", headers=ha).json()["memories"]]
    check("one fact left", left == ["User speaks Roman Urdu"], str(left))
    # Delete a missing id -> 404.
    check("delete missing 404",
          c.delete("/user/memories/nope1234", headers=ha).status_code == 404)
    # Deleting the account wipes its memories.
    check("delete account A", c.delete("/auth/account", headers=ha).status_code == 200)
    check("memories gone with account",
          authmod.list_memories(ra.json()["user"]["id"]) == [])
    c.delete("/auth/account", headers=hb)


async def test_runtime_wiring():
    import app.agent.runtime as rtmod
    from app.config import settings
    from app.agent.runtime import AgentRuntime

    user, _tok = authmod.register("v04-rt@example.com", "testpass123")
    uid = user["id"]

    # --- Task 1: stubbed LLM calls fetch_url on a blocked address ---
    rt = AgentRuntime(settings, "t1", "Check http://169.254.169.254/ for me", authed=True, user_id=uid)
    script = [
        {"plan": "fetch the metadata endpoint", "tool": "fetch_url",
         "args": {"url": "http://169.254.169.254/latest/meta-data/"}, "verify": "observation says blocked"},
        {"plan": "report", "tool": "finish", "args": {"result": "done"}, "verify": "n/a"},
    ]

    async def fake_generate(prompt, timeout=20):
        step = script.pop(0)
        return json.dumps(step), "stub-model"

    rt.provider.generate = fake_generate
    out = await rt.run()
    obs = [s["observation"] for s in out["steps"]]
    check("runtime fetch_url dispatched + SSRF blocked",
          any("FETCH BLOCKED" in o for o in obs), str(obs)[:200])

    # --- Task 2: stubbed LLM fetches example.com (success path, via stub resolver) ---
    async def fetch_stub(url):
        from app.fetch import fetch_url as real_fetch
        return await real_fetch(url, _resolver=_stub_resolver)

    rtmod.fetch_url = fetch_stub
    try:
        rt2 = AgentRuntime(settings, "t2", "What does example.com say?", authed=True, user_id=uid)
        script2 = [
            {"plan": "fetch the page", "tool": "fetch_url",
             "args": {"url": "https://example.com"}, "verify": "observation has Example Domain"},
            {"plan": "report", "tool": "finish",
             "args": {"result": "> Example.com is a demo domain.\n\n**Example Domain** is a placeholder page for illustrative examples."},
             "verify": "n/a"},
        ]

        async def fake_generate2(prompt, timeout=20):
            step = script2.pop(0)
            return json.dumps(step), "stub-model"

        rt2.provider.generate = fake_generate2
        out2 = await rt2.run()
        obs2 = [s["observation"] for s in out2["steps"]]
        check("runtime fetch_url success path (example.com)",
              any("Example Domain" in o for o in obs2), str(obs2)[:200])
        check("runtime task completed", out2["status"] == "completed", out2["status"])
    finally:
        from app.fetch import fetch_url as real_fetch2
        rtmod.fetch_url = real_fetch2

    # --- Task 3: stubbed LLM saves a fact with remember ---
    rt3 = AgentRuntime(settings, "t3", "Remember that my favourite editor is VS Code", authed=True, user_id=uid)
    script3 = [
        {"plan": "save the fact", "tool": "remember",
         "args": {"fact": "User's favourite editor is VS Code"}, "verify": "observation says Saved"},
        {"plan": "report", "tool": "finish", "args": {"result": "Saved."}, "verify": "n/a"},
    ]

    async def fake_generate3(prompt, timeout=20):
        step = script3.pop(0)
        return json.dumps(step), "stub-model"

    rt3.provider.generate = fake_generate3
    out3 = await rt3.run()
    obs3 = [s["observation"] for s in out3["steps"]]
    check("runtime remember dispatched + saved",
          any("Saved to memory" in o for o in obs3), str(obs3)[:200])
    check("fact persisted in DB",
          any(m["fact"] == "User's favourite editor is VS Code" for m in authmod.list_memories(uid)),
          str(authmod.list_memories(uid)))

    # --- Task 4: a later task recalls the fact (injected into the prompt) ---
    captured = {}

    async def fake_generate4(prompt, timeout=20):
        captured["prompt"] = prompt
        return json.dumps({"plan": "answer", "tool": "finish",
                           "args": {"result": "Your favourite editor is VS Code."}, "verify": "n/a"}), "stub-model"

    rt4 = AgentRuntime(settings, "t4", "What is my favourite editor?", authed=True, user_id=uid)
    rt4.provider.generate = fake_generate4
    out4 = await rt4.run()
    check("later task recalls the fact",
          "User's favourite editor is VS Code" in captured.get("prompt", ""),
          "fact in prompt: " + str("User's favourite editor is VS Code" in captured.get("prompt", "")))
    check("recall task completed", out4["status"] == "completed", out4["status"])

    # --- Guest: remember is login-gated (runtime blocks non-finish tools) ---
    rtg = AgentRuntime(settings, "t5", "Remember my name is Hammad", authed=False, user_id=None)

    async def fake_generate5(prompt, timeout=20):
        return json.dumps({"plan": "save", "tool": "remember",
                           "args": {"fact": "Guest name is Hammad"}, "verify": "n/a"}), "stub-model"

    rtg.provider.generate = fake_generate5
    out5 = await rtg.run()
    check("guest remember blocked by login gate",
          out5["status"] == "completed" and "log in" in (out5.get("result") or "").lower(),
          str(out5.get("result"))[:120])
    authmod.delete_account(uid)


async def main():
    await test_fetch_ssrf_blocks()
    await test_validate_host()
    test_html_extraction()
    test_json_pretty()
    await test_fetch_success()
    await test_redirect_logic()
    test_memory_endpoints()
    await test_runtime_wiring()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL v0.4 TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
