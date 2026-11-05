import os, json, sqlite3, uuid, asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .config import settings
from .agent.runtime import AgentRuntime
app = FastAPI(title="Cyber Agent Cloud", version="0.3")
DB = os.path.join(settings.data_dir, "tasks.db")
os.makedirs(settings.data_dir, exist_ok=True)
def db():
    c = sqlite3.connect(DB); c.execute("CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, prompt TEXT, status TEXT, result TEXT, created TEXT)")
    return c
class TaskIn(BaseModel):
    prompt: str
    target: str | None = None
runtimes = {}
@app.get("/health")
def health(): return {"ok": True, "service": "cyber-agent-cloud", "version": "0.3", "gemini_configured": bool(settings.gemini_api_key), "allowed_domains": settings.allowed_domains}
@app.post("/tasks")
async def create_task(t: TaskIn):
    tid = uuid.uuid4().hex[:12]
    c = db(); c.execute("INSERT INTO tasks VALUES (?,?,?,?,datetime('now'))", (tid, t.prompt, "running", "")); c.commit(); c.close()
    rt = AgentRuntime(settings, tid, t.prompt)
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
