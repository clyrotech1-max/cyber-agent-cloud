import os
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
