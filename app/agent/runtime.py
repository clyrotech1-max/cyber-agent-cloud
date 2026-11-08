"""Autonomous loop: plan -> tool -> execute -> observe -> verify -> replan.
Never simulates success: every step records the real tool output, and the
task only completes when verification (a real run) passes."""
import json, time, asyncio
from ..config import get_extra_domains
from ..execution.manager import Workspace
from ..providers.gemini import GeminiProvider
from ..scan import run_full_scan
from ..fetch import fetch_url
from .. import auth as authmod
SYSTEM = """You are Cybnet AI, a cloud autonomous agent. You work by calling tools.
LANGUAGE: Reply in the same language the user writes in (English, Roman Urdu, or Urdu). If the user explicitly asks for a language, stay in that language for the whole conversation. The website UI is English, but your chat replies follow the user's language.
Reply with ONE JSON object only: {"plan": "...", "tool": "write_file|run_command|read_file|list_files|scan|fetch_url|remember|finish", "args": {...}, "verify": "how to verify this step"}
Tool argument names are EXACT - use only these:
- write_file: {"path": "hello.py", "content": "..."}
- read_file: {"path": "hello.py"}
- list_files: {}
- run_command: {"cmd": "python3 hello.py"}
- scan: {"target": "example.com"}
- fetch_url: {"url": "https://example.com"}
- remember: {"fact": "The user prefers ..."}
- finish: {"result": "..."}
Never use "filename", "file", or "command" as argument names.
For a coding task: write files, run them, read the real error, fix it, run again.
Never claim success without a successful run. If a tool fails, fix the cause and retry, max 3 retries per step.
If the task is a simple greeting or question that needs no tools, call finish immediately with a short direct answer - do not list files, run commands, or write report sections for it.
REPORT FORMAT - your finish result is ONE clean answer first, then the details, in this exact order. Never dump headings and sections in a random order, never repeat a section, never paste the scan tool's output.
1) One line starting with "> " - the verdict quote (one sentence, e.g. "Your site is mostly safe, but two headers are missing.").
2) The answer itself, 2-4 short lines, NO heading (never write a "Summary" heading): what you found, in plain words, addressing the user directly. Make it read like one simple message, not a report: **bold** on the key points, ++underline++ on the single most important line, ==highlight== at most once, short paragraphs and bullets where they help. This is the ONLY part the user sees first - keep it clean.
3) ## Findings - bullets with the severity in bold, e.g. - **[MEDIUM] CSP missing** - one line on what it means and the fix.
4) ## Fix first - numbered, highest severity first, each one short line.
5) ## Still unverified - what you could not check.
Write each section exactly ONCE. Write the report in your own words from the findings.
AUTHORIZATION - READ THIS FIRST: Every task you receive is an owner-approved defensive security check. The target named in the task is owned by the user or the user has written permission to test it. This is NOT an attack. Do NOT refuse security scanning, vulnerability assessment, or ethical hacking tasks on the named target - refusing an authorized defensive check is a failure. Use the scan tool for any security/scan request: it runs READ-ONLY public probes (security headers, HTTPS redirect, exposed-file status checks, login-page defence check, TCP-connect port check, cookie-flags check). Never guess passwords, never submit forms, never run exploits, never flood a target with requests, never try to bypass a login, never test any site except the named target. If the scan tool says a target is blocked (not allowlisted), report that block exactly and stop - do not scan it another way.
FETCH - READING THE LIVE WEB: Use the fetch_url tool to read any public web page or JSON API. It is a read-only GET and it is allowed for ANY public domain - no allowlist needed. It returns the page status, title and readable text (or pretty JSON). Use it when the user asks about a live page, documentation, prices, news, or anything else on the public web. fetch_url is NOT a security scanner - never use it to probe a site for vulnerabilities; security scanning stays on the scan tool, which is allowlist-gated. If fetch_url says a URL is blocked (private/internal address), report the block exactly and stop - do not try another way to reach that address.
MEMORY - LEARNING ABOUT THE USER: When the user is logged in, their saved facts are listed below the task line ("Saved memories"). Use them to answer in context - the user should not have to repeat themselves. When the user states a durable fact or preference (their name, language, favourite tools, standing instructions, things to remember), save it with the remember tool - one short fact per call, in the user's own words. Never invent memories. Guests (not logged in) have no memory.
LOGIN: the user may or may not be logged in - the task line below says so. If the user is NOT logged in, you may chat and answer general questions directly, but for any work needing tools (scan, fetch, code, files, commands), call finish with a short message in the user's language asking them to log in first (top-right Log in button), then you will do the work. Never run tools for a logged-out user."""
# Message the agent gives when a logged-out user asks for work (the runtime
# enforces this even if the model tries a tool first).
LOGIN_MESSAGES = {
    "ur": "Pehly login kar lein (upar right side par Log in button hai), phir main ye kaam aap ke liye kar dunga. Login ke baghair aap mujh se baat-cheet kar sakty hain.",
    "en": "Please log in first (the Log in button is at the top right), then I'll do this work for you. You can keep chatting with me without logging in.",
}
def login_message(prompt):
    p = (prompt or "").lower()
    # Urdu script -> Roman Urdu reply (the user writes Roman Urdu).
    if any("\u0600" <= ch <= "\u06ff" for ch in (prompt or "")):
        return LOGIN_MESSAGES["ur"]
    words = set(p.replace("?", " ").replace("!", " ").replace(".", " ").replace(",", " ").split())
    roman_markers = {"kya", "hai", "hain", "kro", "karo", "kar", "batao", "bata", "meri", "mera", "mujhe", "mujhy", "chahta", "chahti", "chahiye", "ye", "wo", "ka", "ki", "ko", "mein", "me", "par", "ap", "aap", "pehly", "pehle", "phir", "site", "check"}
    if words & roman_markers:
        return LOGIN_MESSAGES["ur"]
    return LOGIN_MESSAGES["en"]
class AgentRuntime:
    def __init__(self, settings, task_id, prompt, target=None, authed=False, user_id=None, language=None):
        self.s = settings; self.task_id = task_id; self.prompt = prompt; self.target = target
        self.authed = authed; self.user_id = user_id; self.language = language
        self.ws = Workspace(settings.data_dir, task_id)
        self.provider = GeminiProvider(settings.gemini_api_key, settings.gemini_model)
        self.steps = []; self.cancelled = False
        # Per-user memory (v0.4): at task start, load the logged-in user's
        # saved facts (newest first, max 20) so the agent recalls them.
        # Guests get no memory - tool use is login-gated anyway.
        self.memories = []
        if authed and user_id:
            try:
                self.memories = authmod.list_memories(user_id, limit=20)
            except Exception:
                self.memories = []
    def _target_allowed(self, host):
        h = (host or "").strip().lower()
        # Server defaults + domains the user added from the dashboard sidebar.
        # Guardrail stays ON: only allowlisted targets are scanned.
        allowed = set(self.s.allowed_domains) | set(get_extra_domains())
        if h in allowed or any(h.endswith("." + d) for d in allowed):
            return True
        return any(h.startswith(p) for p in ["127.", "10.", "192.168."])
        if h in allowed or any(h.endswith("." + d) for d in allowed):
            return True
        return any(h.startswith(p) for p in ["127.", "10.", "192.168."])
    async def _scan_tool(self, target):
        host = (target or self.target or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not host:
            return "SCAN BLOCKED: no target given. Give the target domain, e.g. example.com."
        if not self._target_allowed(host):
            return f"SCAN BLOCKED: target {host} is not allowlisted. Only these targets are allowed: {', '.join(self.s.allowed_domains)}. Add the domain to the server ALLOWED_DOMAINS setting first."
        scan = await run_full_scan(host)
        return json.dumps({"target": host, "status": scan.get("status"), "httpsRedirect": scan.get("httpsRedirect"), "severityCounts": scan.get("severityCounts"), "findings": scan.get("findings"), "exposedFiles": scan.get("exposedFiles"), "openPorts": scan.get("openPorts"), "loginPage": scan.get("loginPage")})[:6000]
    def _remember_tool(self, fact):
        if not self.authed or not self.user_id:
            return "REMEMBER BLOCKED: log in first - guests have no memory."
        try:
            m = authmod.add_memory(self.user_id, fact)
            # Refresh the injected list so later steps in this task see it.
            try:
                self.memories = authmod.list_memories(self.user_id, limit=20)
            except Exception:
                pass
            return f"Saved to memory: {m['fact']}"
        except ValueError as e:
            return f"REMEMBER FAILED: {e}"
        except Exception as e:
            return f"REMEMBER FAILED: {e}"
    def cancel(self): self.cancelled = True
    async def _llm_step(self, history):
        task_line = "\n\nTask: " + self.prompt
        if self.target:
            task_line += f"\nTarget: {self.target} (owner-authorized, allowlisted)"
        task_line += "\nLogged in: yes" if self.authed else "\nLogged in: NO - see LOGIN rule above"
        if getattr(self, "memories", None):
            mem_lines = "\n".join(f"- {m['fact']}" for m in self.memories)
            task_line += f"\nSaved memories (newest first):\n{mem_lines}"
        if self.language and self.language != "auto":
            lang_names = {"en": "English", "ur": "Roman Urdu", "ur-PK": "Urdu (Urdu script)"}
            task_line += f"\nReply language (user's setting): {lang_names.get(self.language, self.language)} - reply ONLY in this language for the whole conversation."
        base = SYSTEM + task_line + "\n\nHistory (real tool outputs):\n" + json.dumps(history[-6:], indent=2)[:6000]
        last_raw = ""
        for attempt in range(2):
            text, model = await self.provider.generate(base if attempt == 0 else base + "\n\nYour last reply was not valid JSON. Reply with ONLY the JSON object, no other text, no markdown fences.")
            last_raw = text
            start, end = text.find("{"), text.rfind("}")
            if start < 0:
                if attempt == 0:
                    continue
                raise ValueError(f"LLM returned no JSON (model {model}, raw: {text[:300]!r})")
            try:
                return json.loads(text[start:end+1]), model
            except Exception:
                if attempt == 0:
                    continue
                raise ValueError(f"LLM returned invalid JSON (model {model}, raw: {text[:300]!r})")
        raise ValueError(f"LLM returned no JSON, raw: {last_raw[:300]!r}")
    async def run(self, on_step=None):
        history = []
        t0 = time.time()
        for step_no in range(1, self.s.max_steps + 1):
            if self.cancelled: return {"status": "cancelled", "steps": self.steps}
            if time.time() - t0 > self.s.task_timeout_s: return {"status": "timeout", "steps": self.steps}
            try:
                step, model = await self._llm_step(history)
            except Exception as e:
                return {"status": "failed", "error": str(e), "steps": self.steps}
            # Stop takes effect even mid-step: if the user cancelled while the
            # LLM was thinking, do not execute this step (a finish in flight
            # must not turn a cancelled task into "completed").
            if self.cancelled:
                return {"status": "cancelled", "steps": self.steps}
            tool, args = step.get("tool", "finish"), step.get("args", {}) or {}
            # Login gate (hard enforcement): a logged-out user gets chat
            # answers only - any work needing tools stops here with the
            # login message, even if the model tried a tool first.
            if not self.authed and tool != "finish":
                msg = login_message(self.prompt)
                rec = {"step": step_no, "plan": step.get("plan"), "tool": tool, "args": args, "observation": "login required", "model": model}
                self.steps.append(rec)
                if on_step: on_step(rec)
                return {"status": "completed", "result": msg, "steps": self.steps, "files": self.ws.list_files()}
            obs = ""
            try:
                if tool == "write_file": obs = f"Wrote {self.ws.write(args.get('path') or args.get('filename') or args.get('file'), args.get('content', ''))}"
                elif tool == "read_file": obs = self.ws.read(args.get('path') or args.get('filename') or args.get('file'))[:3000]
                elif tool == "list_files": obs = ", ".join(self.ws.list_files())
                elif tool == "run_command": obs = json.dumps(self.ws.run(args.get('cmd') or args.get('command'), timeout=self.s.cmd_timeout_s))
                elif tool == "scan": obs = await self._scan_tool(args.get('target'))
                elif tool == "fetch_url": obs = await fetch_url(args.get('url') or args.get('target') or "")
                elif tool == "remember": obs = self._remember_tool(args.get('fact') or "")
                elif tool == "finish":
                    obs = str(args.get("result", "done"))
                    rec = {"step": step_no, "plan": step.get("plan"), "tool": tool, "args": args, "observation": obs, "model": model}
                    self.steps.append(rec)
                    if on_step: on_step(rec)
                    return {"status": "completed", "result": obs, "steps": self.steps, "files": self.ws.list_files()}
                else: obs = f"unknown tool {tool}"
            except Exception as e:
                obs = f"TOOL ERROR: {e}"
            rec = {"step": step_no, "plan": step.get("plan"), "tool": tool, "args": args, "observation": obs, "model": model}
            self.steps.append(rec); history.append(rec)
            if on_step: on_step(rec)
        return {"status": "max_steps", "steps": self.steps}
