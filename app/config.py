import os, re, sqlite3
class Settings:
    gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
    database_url = os.environ.get("DATABASE_URL", "")  # postgres://... in cloud, else sqlite file
    data_dir = os.environ.get("DATA_DIR", "data")
    max_steps = int(os.environ.get("AGENT_MAX_STEPS", "8"))
    task_timeout_s = int(os.environ.get("AGENT_TASK_TIMEOUT_S", "180"))
    cmd_timeout_s = int(os.environ.get("AGENT_CMD_TIMEOUT_S", "30"))
    max_workspace_mb = int(os.environ.get("AGENT_MAX_WORKSPACE_MB", "100"))
    allowed_domains = [d.strip() for d in os.environ.get("ALLOWED_DOMAINS", "example.com,example.org,hammadtools.com").split(",") if d.strip()]
settings = Settings()

# --- sidebar-added allowlist domains (saved in the same SQLite DB as chats) ---
# The guardrail stays ON: the agent only scans allowlisted targets. Domains the
# user adds from the dashboard sidebar are stored here so the cloud agent and
# the /scan endpoint accept them without touching Render env vars.
# NOTE: same limit as chats - the DB is on ephemeral disk, so sidebar-added
# domains survive sleep but are lost on redeploy/restart.
def _extra_db():
    os.makedirs(settings.data_dir, exist_ok=True)
    c = sqlite3.connect(os.path.join(settings.data_dir, "tasks.db"))
    c.execute("CREATE TABLE IF NOT EXISTS allowed_extra (domain TEXT PRIMARY KEY)")
    return c
def _clean_domain(d):
    return (d or "").strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
def get_extra_domains():
    try:
        c = _extra_db(); rows = c.execute("SELECT domain FROM allowed_extra").fetchall(); c.close()
        return sorted(r[0] for r in rows)
    except Exception:
        return []
def add_extra_domain(domain):
    d = _clean_domain(domain)
    if not re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", d, re.I):
        return None
    c = _extra_db(); c.execute("INSERT OR IGNORE INTO allowed_extra VALUES (?)", (d,)); c.commit(); c.close()
    return d
def remove_extra_domain(domain):
    d = _clean_domain(domain)
    c = _extra_db(); c.execute("DELETE FROM allowed_extra WHERE domain=?", (d,)); c.commit(); c.close()
    return d
def all_allowed_domains():
    return sorted(set(settings.allowed_domains) | set(get_extra_domains()))
