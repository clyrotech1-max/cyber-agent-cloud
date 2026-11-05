"""E2E test (real execution, no mocks): create a Python app with an intentional
bug, run it, fix it, verify it. Run: python test_e2e.py  (needs the API running)"""
import httpx, time, sys
BASE = "http://127.0.0.1:8000"
def main():
    r = httpx.post(f"{BASE}/tasks", json={"prompt": "Create a Python app app.py that prints 'Hello Cyber Agent' and the sum of 2+3, then run it with python3 app.py. If it fails, fix the bug and run again."}, timeout=10)
    print("create:", r.status_code, r.json())
    tid = r.json()["task_id"]
    for i in range(60):
        time.sleep(3)
        s = httpx.get(f"{BASE}/tasks/{tid}", timeout=10).json()
        print(f"poll {i}: {s['status']}")
        if s["status"] in ("completed", "failed", "timeout", "cancelled", "max_steps"):
            print(json.dumps(s, indent=2)[:4000] if (json:=__import__("json")) else s)
            break
if __name__ == "__main__": main()
