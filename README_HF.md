---
title: Cyber Agent Cloud
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
app_port: 7860
---

# Cyber Agent Cloud — Hugging Face Space

FastAPI autonomous agent backend (v0.3). This file is the Space README for
Hugging Face; copy its frontmatter to the top of `README.md` in the Space repo.

Endpoints:
- `GET /health` — `{"ok":true,"service":"cyber-agent-cloud","version":"0.3",...}`
- `POST /tasks` — create an agent task `{"prompt": "...", "target": "..."}`
- `GET /tasks/{id}` — task status + result
- `POST /tasks/{id}/cancel`
- `WS /ws/tasks/{id}` — live steps

Secrets (set in Space Settings → Variables and secrets, never in the repo):
- `GEMINI_API_KEY` — AI Studio key (AIza…), required for the agent LLM.
  Without it tasks fail honestly with "GEMINI_API_KEY is not set".
- `GEMINI_MODEL` — default `gemini-flash-latest`
- `ALLOWED_DOMAINS` — default `example.com,example.org,hammadtools.com`

Notes: free CPU Basic sleeps after inactivity (cold start ~30-60s);
SQLite task history lives in `data/` and is wiped on Space restart/rebuild.
