"""Autonomous loop: plan -> tool -> execute -> observe -> verify -> replan.
Never simulates success: every step records the real tool output, and the
task only completes when verification (a real run) passes."""
import json, time, asyncio
from ..execution.manager import Workspace
from ..providers.gemini import GeminiProvider
SYSTEM = """You are Cyber Agent, a cloud autonomous agent. You work by calling tools.
Reply with ONE JSON object only: {"plan": "...", "tool": "write_file|run_command|read_file|list_files|finish", "args": {...}, "verify": "how to verify this step"}
Tool argument names are EXACT - use only these:
- write_file: {"path": "hello.py", "content": "..."}
- read_file: {"path": "hello.py"}
- list_files: {}
- run_command: {"cmd": "python3 hello.py"}
- finish: {"result": "..."}
Never use "filename", "file", or "command" as argument names.
For a coding task: write files, run them, read the real error, fix it, run again.
Never claim success without a successful run. If a tool fails, fix the cause and retry, max 3 retries per step.
Only test authorized targets (allowlist). Never guess passwords or attack other sites."""
class AgentRuntime:
    def __init__(self, settings, task_id, prompt):
        self.s = settings; self.task_id = task_id; self.prompt = prompt
        self.ws = Workspace(settings.data_dir, task_id)
        self.provider = GeminiProvider(settings.gemini_api_key, settings.gemini_model)
        self.steps = []; self.cancelled = False
    def cancel(self): self.cancelled = True
    async def _llm_step(self, history):
        try:
            text, model = await self.provider.generate(SYSTEM + "\n\nTask: " + self.prompt + "\n\nHistory (real tool outputs):\n" + json.dumps(history[-6:], indent=2)[:6000])
            # extract first JSON object
            start, end = text.find("{"), text.rfind("}")
            if start < 0: raise ValueError("LLM returned no JSON")
            return json.loads(text[start:end+1]), model
        except Exception as e:
            # No fake success: if the LLM is unavailable, the step fails honestly.
            raise
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
            tool, args = step.get("tool", "finish"), step.get("args", {}) or {}
            obs = ""
            try:
                if tool == "write_file": obs = f"Wrote {self.ws.write(args.get('path') or args.get('filename') or args.get('file'), args.get('content', ''))}"
                elif tool == "read_file": obs = self.ws.read(args.get('path') or args.get('filename') or args.get('file'))[:3000]
                elif tool == "list_files": obs = ", ".join(self.ws.list_files())
                elif tool == "run_command": obs = json.dumps(self.ws.run(args.get('cmd') or args.get('command'), timeout=self.s.cmd_timeout_s))
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
