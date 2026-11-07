import os, json, re, sqlite3, uuid, asyncio, time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .config import settings, get_extra_domains, add_extra_domain, remove_extra_domain, all_allowed_domains
from .agent.runtime import AgentRuntime
from .scan import run_full_scan, build_report
from . import auth as authmod
app = FastAPI(title="Cybnet AI Cloud", version="0.3")
DB = os.path.join(settings.data_dir, "tasks.db")
os.makedirs(settings.data_dir, exist_ok=True)
def db():
    c = sqlite3.connect(DB); c.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, prompt TEXT, status TEXT, result TEXT, created TEXT)")
    return c
# --- chat history is NOT stored on the server (privacy): chats live only in
# each user's own browser (localStorage), so no user's chats can ever leak to
# another user. There is intentionally no /chats endpoint. ---
# --- auth (email + password, optional: the web works without login, but
# agent work needs a login) ---
def _bearer_token(request: Request):
    h = request.headers.get("authorization") or ""
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return request.headers.get("x-auth-token") or ""

def _current_user(request: Request):
    return authmod.get_user_by_token(_bearer_token(request))

def _require_user(request: Request):
    u = _current_user(request)
    if not u:
        return None
    return u

class AuthIn(BaseModel):
    email: str = ""
    password: str = ""
class ChangePwIn(BaseModel):
    old_password: str = ""
    new_password: str = ""
class UserChatsIn(BaseModel):
    chats: list = []
class UserSettingsIn(BaseModel):
    settings: dict = {}
@app.post("/auth/register")
def auth_register(body: AuthIn):
    try:
        user, token = authmod.register(body.email, body.password)
        return {"ok": True, "user": user, "token": token}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
@app.post("/auth/login")
def auth_login(body: AuthIn):
    try:
        user, token = authmod.login(body.email, body.password)
        return {"ok": True, "user": user, "token": token}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=401)
@app.post("/auth/logout")
def auth_logout(request: Request):
    authmod.logout(_bearer_token(request))
    return {"ok": True}
@app.get("/auth/me")
def auth_me(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"ok": True, "user": u}
@app.post("/auth/change-password")
def auth_change_password(body: ChangePwIn, request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    try:
        token = authmod.change_password(u["id"], body.old_password, body.new_password)
        return {"ok": True, "token": token}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
@app.delete("/auth/account")
def auth_delete_account(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    authmod.delete_account(u["id"])
    return {"ok": True}
@app.get("/user/chats")
def user_get_chats(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"ok": True, "chats": authmod.get_user_chats(u["id"])}
@app.post("/user/chats")
def user_save_chats(body: UserChatsIn, request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    authmod.save_user_chats(u["id"], body.chats)
    return {"ok": True, "count": len(body.chats)}
@app.get("/user/settings")
def user_get_settings(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"ok": True, "settings": authmod.get_user_settings(u["id"])}
@app.post("/user/settings")
def user_save_settings(body: UserSettingsIn, request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Not logged in."}, status_code=401)
    return {"ok": True, "settings": authmod.save_user_settings(u["id"], body.settings)}
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
    # Work needs a login (the agent says so in chat when logged out).
    if not _current_user(request):
        return JSONResponse({"login_required": True, "error": "Pehly login karein, phir scan hoga."}, status_code=401)
    ip = (request.headers.get("x-forwarded-for") or "unknown").split(",")[0].strip()
    now = time.time()
    arr = [t for t in _scan_hits.get(ip, []) if now - t < 60]
    arr.append(now); _scan_hits[ip] = arr
    if len(arr) > 10:
        return JSONResponse({"error": "Rate limit: 10 scans per minute. Wait 1 minute and try again."}, status_code=429)
    host = _clean_domain(body.target or "")
    if not host or not _valid_domain(host):
        return JSONResponse({"blocked": True, "reason": f"Valid domain likho, jaise example.com. Mila: {host or '(khali)'}"}, status_code=400)
    if not _allowed(host, body.allowedDomains):
        return JSONResponse({"blocked": True, "reason": f"Target is not in the allowlist: {host}. Add your domain in the sidebar under 'Allowed Domains', or use example.com for the demo."}, status_code=403)
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
    language: str | None = None
runtimes = {}
@app.get("/health")
def health(): return {"ok": True, "service": "cybnet-ai-cloud", "version": "0.3", "gemini_configured": bool(settings.gemini_api_key), "allowed_domains": settings.allowed_domains}
@app.post("/tasks")
async def create_task(t: TaskIn, request: Request):
    tid = uuid.uuid4().hex[:12]
    c = db(); c.execute("INSERT INTO tasks VALUES (?,?,?,?,datetime('now'))", (tid, t.prompt, "running", "")); c.commit(); c.close()
    # Login is optional to open/use the web, but agent WORK needs a login:
    # the runtime answers greetings + general questions when logged out, and
    # asks the user to log in first for any work needing tools.
    u = _current_user(request)
    rt = AgentRuntime(settings, tid, t.prompt, t.target, authed=bool(u), user_id=u["id"] if u else None, language=t.language)
    runtimes[tid] = rt
    async def _run():
        try:
            out = await rt.run()
            c = db()
            # A task the user cancelled stays cancelled: a late "completed"
            # from an in-flight step must not overwrite the cancelled status.
            cur = c.execute("SELECT status FROM tasks WHERE id=?", (tid,)).fetchone()
            if cur and cur[0] == "cancelled":
                c.execute("UPDATE tasks SET result=? WHERE id=?", (json.dumps(out)[:20000], tid))
            else:
                c.execute("UPDATE tasks SET status=?, result=? WHERE id=?", (out.get("status"), json.dumps(out)[:20000], tid))
            c.commit(); c.close()
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
