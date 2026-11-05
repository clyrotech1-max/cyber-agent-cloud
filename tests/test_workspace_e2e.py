"""Real execution test, no LLM, no mocks: workspace creates a Python app with
an intentional bug, runs it, observes the real error, fixes it, re-runs, verifies."""
import sys
sys.path.insert(0, ".")
from app.execution.manager import Workspace
ws = Workspace("data", "e2e-test")
ws.write("app.py", "print('Hello Cyber Agent')\nprint('sum =', 2 + 3)\nprint(undefined_name)\n")
r1 = ws.run("python3 app.py")
print("run1:", r1["returncode"], r1["stderr"].strip().splitlines()[-1] if r1["stderr"] else "")
assert r1["returncode"] != 0, "bug should fail first run"
ws.write("app.py", "print('Hello Cyber Agent')\nprint('sum =', 2 + 3)\n")
r2 = ws.run("python3 app.py")
print("run2:", r2["returncode"], r2["stdout"])
assert r2["returncode"] == 0 and "Hello Cyber Agent" in r2["stdout"] and "sum = 5" in r2["stdout"]
print("E2E WORKSPACE PASS - files:", ws.list_files())
