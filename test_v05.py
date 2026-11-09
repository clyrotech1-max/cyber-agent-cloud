"""v0.5 tests: JSON repair, /tasks rate limiting, shell hardening,
security headers, /allowed-domains login gating, Avin rebrand.

Run:  .venv/bin/python test_v05.py
Uses a throwaway DATA_DIR (/tmp/cybnet-v05-test-data) - never the real data/.
No real Gemini key is needed: the runtime tests stub the LLM
(monkeypatched generate) to prove repair retries + graceful failure.
"""
import asyncio
import json
import os
import shutil
import sys
import time

DATA_DIR = "/tmp/cybnet-v05-test-data"
shutil.rmtree(DATA_DIR, ignore_errors=True)
os.environ["DATA_DIR"] = DATA_DIR
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import auth as authmod  # noqa: E402
from app.config import settings  # noqa: E402
from app.agent.runtime import AgentRuntime, SYSTEM, _json_fail_message  # noqa: E402
import app.main as mainmod  # noqa: E402
from app.execution.manager import Workspace  # noqa: E402
from app.scan import build_report  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# ---------------------------------------------------------------- JSON repair
async def test_json_repair_retries():
    # 1) Truncated JSON first, valid JSON on the repair retry -> completes.
    prompts = []

    async def fake_generate(prompt, timeout=20):
        prompts.append(prompt)
        if len(prompts) == 1:
            return '{"plan": "search", "tool": "web_search", "args": {"query": "TRUNC_MARKER_123', "stub-model"
        return json.dumps({"plan": "report", "tool": "finish",
                           "args": {"result": "done TRUNC_MARKER_123"}, "verify": "n/a"}), "stub-model"

    rt = AgentRuntime(settings, "j1", "Find Daily Hayat", authed=True, user_id=None)
    rt.provider.generate = fake_generate
    out = await rt.run()
    check("truncated JSON repaired on retry -> completed",
          out["status"] == "completed", out["status"])
    check("repair hint contained the raw text",
          len(prompts) >= 2 and "TRUNC_MARKER_123" in prompts[1],
          f"calls={len(prompts)}")
    check("repaired result used",
          "TRUNC_MARKER_123" in (out.get("result") or ""), str(out.get("result"))[:80])


async def test_json_repair_graceful():
    # 2) Garbage 3 times -> task COMPLETES (not failed) with a clear message.
    calls = {"n": 0}

    async def fake_garbage(prompt, timeout=20):
        calls["n"] += 1
        return "this is not json at all {{{", "stub-model"

    rt = AgentRuntime(settings, "j2", "What does example.com say?", authed=True, user_id=None)
    rt.provider.generate = fake_garbage
    out = await rt.run()
    check("garbage x3 -> completed not failed",
          out["status"] == "completed", out["status"])
    check("exactly 3 attempts (initial + 2 retries)",
          calls["n"] == 3, f"calls={calls['n']}")
    check("graceful message asks to retry",
          "send your message again" in (out.get("result") or "").lower(),
          str(out.get("result"))[:120])
    check("no raw error in result",
          "LLM returned invalid JSON" not in (out.get("result") or ""),
          str(out.get("result"))[:120])

    # 3) No JSON at all, 3 times -> same graceful path.
    async def fake_nojson(prompt, timeout=20):
        return "just some plain text, no braces", "stub-model"

    rt2 = AgentRuntime(settings, "j3", "ye kya hai", authed=True, user_id=None)
    rt2.provider.generate = fake_nojson
    out2 = await rt2.run()
    check("no-JSON x3 -> completed not failed",
          out2["status"] == "completed", out2["status"])
    check("Roman Urdu prompt -> Roman Urdu graceful message",
          "dobara bhej dein" in (out2.get("result") or ""),
          str(out2.get("result"))[:120])


def test_json_fail_message_languages():
    check("english fail message",
          "send your message again" in _json_fail_message("What is example.com?"))
    check("roman urdu fail message",
          "dobara bhej dein" in _json_fail_message("ye site kya hai"))
    check("urdu script fail message",
          "dobara bhej dein" in _json_fail_message("یہ سائٹ کیا ہے"))


# ------------------------------------------------------------ rate limiting
def test_rate_limit_tasks():
    from fastapi.testclient import TestClient
    c = TestClient(mainmod.app)
    mainmod._task_hits.clear()

    def post(ip):
        return c.post("/tasks", json={"prompt": "hello"},
                      headers={"X-Forwarded-For": ip})

    # 3/min: first three OK, fourth 429.
    ip = "203.0.113.9"
    codes = [post(ip).status_code for _ in range(4)]
    check("3 tasks/min allowed", codes[:3] == [200, 200, 200], str(codes))
    r4 = post(ip)
    check("4th task in a minute -> 429",
          r4.status_code == 429 and "3 tasks per minute" in r4.json().get("error", ""),
          f"{r4.status_code} {r4.text[:120]}")
    check("429 carries Retry-After", "retry-after" in r4.headers, str(dict(r4.headers)))

    # A different IP is unaffected.
    check("different IP still allowed",
          post("203.0.113.10").status_code == 200)

    # Rightmost XFF value is the key: seed 3 hits for the rightmost IP,
    # then a request whose LEFTMOST is fresh but rightmost is the seeded
    # one must still be limited.
    mainmod._task_hits.clear()
    mainmod._task_hits["203.0.113.9"] = [time.time()] * 3
    r = c.post("/tasks", json={"prompt": "hello"},
               headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.9"})
    check("rightmost XFF value is the rate-limit key",
          r.status_code == 429, f"{r.status_code} {r.text[:100]}")
    r2 = c.post("/tasks", json={"prompt": "hello"},
                headers={"X-Forwarded-For": "203.0.113.9, 9.9.9.9"})
    check("leftmost XFF value is NOT the key",
          r2.status_code == 200, f"{r2.status_code}")

    # Hour window: 20 hits 2 minutes ago (outside minute, inside hour).
    mainmod._task_hits.clear()
    mainmod._task_hits["203.0.113.11"] = [time.time() - 120] * 20
    rh = post("203.0.113.11")
    check("20/hr -> 429 hour message",
          rh.status_code == 429 and "20 tasks per hour" in rh.json().get("error", ""),
          f"{rh.status_code} {rh.text[:120]}")

    # Day window: 30 hits ~66 minutes ago (outside hour, inside day).
    mainmod._task_hits.clear()
    mainmod._task_hits["203.0.113.12"] = [time.time() - 4000] * 30
    rd = post("203.0.113.12")
    check("30/day -> 429 day message",
          rd.status_code == 429 and "30 tasks per day" in rd.json().get("error", ""),
          f"{rd.status_code} {rd.text[:120]}")

    mainmod._task_hits.clear()
    check("concurrency semaphore is 3",
          isinstance(mainmod._TASK_SEM, asyncio.Semaphore) and mainmod._TASK_SEM._value == 3,
          str(getattr(mainmod._TASK_SEM, "_value", "?")))


# ------------------------------------------------------------ shell hardening
def test_shell_hardening():
    ws = Workspace(DATA_DIR, "sh1")
    ws.write("hello.txt", "hello world\nsecond line\n")
    r = ws.run("ls")
    check("ls runs", r["returncode"] == 0 and "hello.txt" in r["stdout"], str(r)[:120])
    r = ws.run("cat hello.txt")
    check("cat reads file", r["returncode"] == 0 and "hello world" in r["stdout"], str(r)[:120])
    r = ws.run('echo "hello world"')
    check("quoted args work", r["returncode"] == 0 and r["stdout"].strip() == "hello world",
          str(r)[:120])
    r = ws.run("pwd")
    check("pwd returns workspace root", r["returncode"] == 0 and "sh1" in r["stdout"],
          str(r)[:120])
    r = ws.run("grep hello hello.txt")
    check("grep runs", r["returncode"] == 0 and "hello world" in r["stdout"], str(r)[:120])

    blocked = [
        ("python3 app.py", "python3 blocked"),
        ("node app.js", "node blocked"),
        ("bash -c ls", "bash blocked"),
        ("sh -c ls", "sh blocked"),
        ("curl https://example.com", "curl blocked"),
        ("wget https://example.com", "wget blocked"),
        ("rm -rf /", "rm -rf / blocked"),
        ("ls; rm -rf /", "semicolon blocked"),
        ("ls | grep x", "pipe blocked"),
        ("ls && echo hi", "&& blocked"),
        ("ls || echo hi", "|| blocked"),
        ("echo $(whoami)", "$() blocked"),
        ("echo $HOME", "$VAR blocked"),
        ("echo `id`", "backtick blocked"),
        ("cat hello.txt > out.txt", "redirect > blocked"),
        ("cat hello.txt < in.txt", "redirect < blocked"),
        ("ls\n echo hi", "newline blocked"),
    ]
    for cmd, name in blocked:
        try:
            ws.run(cmd)
            check(name, False, f"ran: {cmd!r}")
        except ValueError as e:
            check(name, True, str(e)[:90])
        except Exception as e:
            check(name, False, f"wrong exception {type(e).__name__}: {e}")

    # shell=False + stripped env, proven by capturing subprocess.run kwargs.
    import app.execution.manager as mgrmod
    import subprocess as _sp
    captured = {}

    class _FakeProc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured.update(kw)
        return _FakeProc()

    real_run = _sp.run
    _sp.run = fake_run
    try:
        ws.run("echo hi")
    finally:
        _sp.run = real_run
    check("subprocess uses shell=False",
          captured.get("shell") is False, str(captured.get("shell")))
    check("subprocess gets argv list, not a string",
          captured.get("argv") == ["echo", "hi"], str(captured.get("argv")))
    check("stripped env has only PATH/HOME/LANG",
          set(captured.get("env", {}).keys()) == {"PATH", "HOME", "LANG"},
          str(sorted(captured.get("env", {}).keys())))


# ------------------------------------------------------------ security headers
def test_security_headers():
    from fastapi.testclient import TestClient
    c = TestClient(mainmod.app)
    r = c.get("/health")
    h = r.headers
    check("HSTS present, no preload",
          h.get("strict-transport-security") == "max-age=31536000; includeSubDomains",
          h.get("strict-transport-security", ""))
    check("X-Content-Type-Options nosniff",
          h.get("x-content-type-options") == "nosniff", h.get("x-content-type-options", ""))
    check("X-Frame-Options DENY",
          h.get("x-frame-options") == "DENY", h.get("x-frame-options", ""))
    check("Referrer-Policy strict-origin-when-cross-origin",
          h.get("referrer-policy") == "strict-origin-when-cross-origin",
          h.get("referrer-policy", ""))
    check("Permissions-Policy present",
          h.get("permissions-policy") == "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
          h.get("permissions-policy", ""))
    check("CSP Report-Only present",
          (h.get("content-security-policy-report-only") or "").startswith("default-src 'self'"),
          (h.get("content-security-policy-report-only") or "")[:60])
    check("API response has Cache-Control no-store",
          h.get("cache-control") == "no-store", h.get("cache-control", ""))
    r2 = c.get("/tasks/doesnotexist123")
    check("task 404 also has headers + no-store",
          r2.status_code == 404 and r2.headers.get("x-frame-options") == "DENY"
          and r2.headers.get("cache-control") == "no-store",
          f"{r2.status_code} {r2.headers.get('cache-control')}")
    r3 = c.post("/auth/login", json={"email": "nobody@example.com", "password": "x"})
    check("auth response has headers + no-store",
          r3.status_code == 401 and r3.headers.get("cache-control") == "no-store"
          and r3.headers.get("x-content-type-options") == "nosniff",
          f"{r3.status_code} {r3.headers.get('cache-control')}")
    # Static frontend: headers yes, no-store NO (static files may cache).
    r4 = c.get("/")
    check("static homepage 200 with headers",
          r4.status_code == 200 and r4.headers.get("x-frame-options") == "DENY",
          f"{r4.status_code}")
    check("static homepage is NOT no-store",
          r4.headers.get("cache-control") != "no-store",
          r4.headers.get("cache-control", "(absent)"))


# ------------------------------------------------- /allowed-domains gating
def test_allowed_domains_gating():
    from fastapi.testclient import TestClient
    c = TestClient(mainmod.app)
    check("GET /allowed-domains 401 logged out",
          c.get("/allowed-domains").status_code == 401)
    check("POST /allowed-domains 401 logged out",
          c.post("/allowed-domains", json={"domain": "example.net"}).status_code == 401)
    check("DELETE /allowed-domains 401 logged out",
          c.delete("/allowed-domains/example.net").status_code == 401)
    reg = c.post("/auth/register", json={"email": "v05-dom@example.com", "password": "testpass123"})
    check("register for domains test", reg.status_code == 200, str(reg.status_code))
    tok = reg.json()["token"]
    hdr = {"Authorization": f"Bearer {tok}"}
    g = c.get("/allowed-domains", headers=hdr)
    check("GET /allowed-domains 200 logged in", g.status_code == 200, str(g.status_code))
    defaults = g.json().get("server_defaults", [])
    check("server defaults still seeded",
          all(d in defaults for d in ["example.com", "example.org", "hammadtools.com", "we.hammadgfx.online"]),
          str(defaults))
    p = c.post("/allowed-domains", json={"domain": "example.net"}, headers=hdr)
    check("POST adds domain logged in",
          p.status_code == 200 and "example.net" in p.json().get("allowed_domains", []),
          str(p.status_code))
    check("GET shows added domain",
          "example.net" in c.get("/allowed-domains", headers=hdr).json().get("allowed_domains", []))
    d = c.delete("/allowed-domains/example.net", headers=hdr)
    check("DELETE removes domain logged in",
          d.status_code == 200 and "example.net" not in d.json().get("allowed_domains", []),
          str(d.status_code))
    check("invalid domain 400 logged in",
          c.post("/allowed-domains", json={"domain": "not a domain!!"}, headers=hdr).status_code == 400)
    c.delete("/auth/account", headers=hdr)


# ------------------------------------------------------------------- rebrand
def test_rebrand():
    check("SYSTEM prompt calls the agent Avin",
          "You are Avin" in SYSTEM, SYSTEM[:80])
    check("SYSTEM prompt has no Cybnet AI",
          "Cybnet AI" not in SYSTEM)
    check("SYSTEM prompt no longer tells the agent to run code",
          "python3" not in SYSTEM)
    scan = {"scannedAt": "2026-11-09T00:00:00+00:00", "url": "https://example.com/",
            "status": 200, "severityCounts": {"high": 0, "medium": 1, "low": 0, "ok": 2},
            "findings": ["[MEDIUM] test"], "exposedFiles": [], "openPorts": [],
            "loginPage": "not found"}
    rep = build_report(scan, "example.com")
    check("scan report title is Avin",
          rep.startswith("# Avin Scan Report - example.com"), rep.splitlines()[0])
    check("scan report has no Cybnet",
          "Cybnet" not in rep)
    # No "Cybnet" (capital C) anywhere in backend source. The lowercase
    # hyphenated "cybnet-ai-cloud" in /health is the service name and
    # stays by design - it does not contain capital-C "Cybnet".
    import pathlib
    root = pathlib.Path(__file__).parent / "app"
    leftovers = [str(p) for p in root.rglob("*.py") if "Cybnet" in p.read_text(encoding="utf-8")]
    check("no Cybnet left in app/*.py", leftovers == [], str(leftovers))
    from fastapi.testclient import TestClient
    c = TestClient(mainmod.app)
    h = c.get("/health").json()
    check("health version is 0.6", h.get("version") == "0.6", str(h.get("version")))
    check("health service field unchanged",
          h.get("service") == "cybnet-ai-cloud", str(h.get("service")))
    import app.fetch as fetchmod
    import app.scan as scanmod
    check("fetch UA is Avin",
          "Avin-Cloud" in fetchmod.UA.get("User-Agent", ""), fetchmod.UA.get("User-Agent", ""))
    check("scan UA is Avin",
          "Avin-Cloud" in scanmod.UA.get("User-Agent", ""), scanmod.UA.get("User-Agent", ""))


async def main():
    await test_json_repair_retries()
    await test_json_repair_graceful()
    test_json_fail_message_languages()
    test_rate_limit_tasks()
    test_shell_hardening()
    test_security_headers()
    test_allowed_domains_gating()
    test_rebrand()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL v0.5 TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
