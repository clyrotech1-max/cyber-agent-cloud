import os, json, re, sqlite3, uuid, asyncio, time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .config import settings, get_extra_domains, add_extra_domain, remove_extra_domain, all_allowed_domains
from .agent.runtime import AgentRuntime
from .scan import run_full_scan, build_report
app = FastAPI(title="Cybnet AI Cloud", version="0.3")
DB = os.path.join(settings.data_dir, "tasks.db")
os.makedirs(settings.data_dir, exist_ok=True)
def db():
    c = sqlite3.connect(DB); c.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, prompt TEXT, status TEXT, result TEXT, created TEXT)"); c.execute("CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, data TEXT)")
    return c
# --- chat history (persisted in backend so chats survive refresh / other devices) ---
class ChatsIn(BaseModel):
    chats: list = []
@app.get("/chats")
def get_chats():
    c = db(); row = c.execute("SELECT data FROM chats WHERE id='main'").fetchone(); c.close()
    return {"chats": json.loads(row[0]) if row and row[0] else []}
@app.post("/chats")
def save_chats(body: ChatsIn):
    data = json.dumps(body.chats)[:500000]
    c = db(); c.execute("INSERT INTO chats VALUES ('main', ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (data,)); c.commit(); c.close()
    return {"ok": True, "count": len(body.chats)}
# --- defensive scan (same guardrail + checks as the web scanner) ---
class ScanIn(BaseModel):
    target: str | None = None
    allowedDomains: list = []
def _clean_domain(d):
    return str(d or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
def _valid_domain(d):
    return bool(re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", d, re.I))
def _allowed(host, extra):
    allowed = set(settings.allowed_domains) | set(get_extra_domains()) | {d for d in (extra or []) if _valid_domain(d)}
    if host in allowed or any(host.endswith("." + d) for d in allowed):
        return True
    return any(host.startswith(p) for p in ["127.", "10.", "192.168."])
# --- allowlist management (dashboard sidebar <-> backend) ---
class DomainIn(BaseModel):
    domain: str = ""
@app.get("/allowed-domains")
def list_allowed_domains():
    return {"allowed_domains": all_allowed_domains(), "server_defaults": settings.allowed_domains, "added": get_extra_domains()}
@app.post("/allowed-domains")
def add_allowed_domain(body: DomainIn):
    d = add_extra_domain(body.domain)
    if not d:
        return JSONResponse({"error": "Valid domain likho, jaise example.com."}, status_code=400)
    return {"ok": True, "domain": d, "allowed_domains": all_allowed_domains()}
@app.delete("/allowed-domains/{domain}")
def delete_allowed_domain(domain: str):
    remove_extra_domain(domain)
    return {"ok": True, "allowed_domains": all_allowed_domains()}
_scan_hits = {}
@app.post("/scan")
async def scan_endpoint(body: ScanIn, request: Request):
    ip = (request.headers.get("x-forwarded-for") or "unknown").split(",")[0].strip()
    now = time.time()
    arr = [t for t in _scan_hits.get(ip, []) if now - t < 60]
    arr.append(now); _scan_hits[ip] = arr
    if len(arr) > 10:
        return JSONResponse({"error": "Rate limit: 10 scans per minute. 1 minute ruk kar dobara try karo."}, status_code=429)
    host = _clean_domain(body.target or "")
    if not host or not _valid_domain(host):
        return JSONResponse({"blocked": True, "reason": f"Valid domain likho, jaise example.com. Mila: {host or '(khali)'}"}, status_code=400)
    if not _allowed(host, body.allowedDomains):
        return JSONResponse({"blocked": True, "reason": f"Target allowlist me nahi hai: {host}. Sidebar ke 'Allowed Domains' section me apna domain add karo, ya demo ke liye example.com use karo."}, status_code=403)
    started = time.time()
    try:
        scan = await run_full_scan(host)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    scan["report"] = build_report(scan, host)
    scan["tookMs"] = int((time.time() - started) * 1000)
    return scan
class TaskIn(BaseModel):
    prompt: str
    target: str | None = None
runtimes = {}
@app.get("/health")
def health(): return {"ok": True, "service": "cybnet-ai-cloud", "version": "0.3", "gemini_configured": bool(settings.gemini_api_key), "allowed_domains": settings.allowed_domains}
@app.post("/tasks")
async def create_task(t: TaskIn):
    tid = uuid.uuid4().hex[:12]
    c = db(); c.execute("INSERT INTO tasks VALUES (?,?,?,?,datetime('now'))", (tid, t.prompt, "running", "")); c.commit(); c.close()
    rt = AgentRuntime(settings, tid, t.prompt, t.target)
    runtimes[tid] = rt
    async def _run():
        try:
            out = await rt.run()
            c = db(); c.execute("UPDATE tasks SET status=?, result=? WHERE id=?", (out.get("status"), json.dumps(out)[:20000], tid)); c.commit(); c.close()
        except Exception as e:
            c = db(); c.execute("UPDATE tasks SET status=?, result=? WHERE id=?", ("failed", str(e), tid)); c.commit(); c.close()
    asyncio.create_task(_run())
    return {"task_id": tid, "status": "running"}
@app.get("/tasks/{tid}")
def get_task(tid: str):
    c = db(); row = c.execute("SELECT id,prompt,status,result FROM tasks WHERE id=?", (tid,)).fetchone(); c.close()
    if not row: return JSONResponse({"error": "not found"}, status_code=404)
    return {"task_id": row[0], "prompt": row[1], "status": row[2], "result": json.loads(row[3]) if row[3] else None}
@app.post("/tasks/{tid}/cancel")
def cancel_task(tid: str):
    rt = runtimes.get(tid)
    if rt: rt.cancel()
    c = db(); c.execute("UPDATE tasks SET status='cancelled' WHERE id=?", (tid,)); c.commit(); c.close()
    return {"task_id": tid, "status": "cancelled"}
@app.websocket("/ws/tasks/{tid}")
async def ws_task(ws: WebSocket, tid: str):
    await ws.accept()
    try:
        while True:
            rt = runtimes.get(tid)
            if rt:
                await ws.send_json({"task_id": tid, "steps": rt.steps})
            await asyncio.sleep(1)
    except WebSocketDisconnect: pass

# --- serve the frontend (static export built from cyber-agent-web) on this same service ---
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
