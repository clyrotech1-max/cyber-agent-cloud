# Cyber Agent — Cloud Autonomous Infrastructure (v0.3 scaffold)

## 1. Existing architecture audit (done 5 Nov 2026)
| Layer | What exists | What is missing |
|---|---|---|
| Frontend | Next.js ChatGPT-style UI at cyber.hammadgfx.online, 255-line page.jsx, sidebar, model selector, Allowed Domains, Key Test | No connection to any cloud backend; Gemini called directly from the user's browser; key in localStorage |
| Backend v0.3 | Next.js `/api/scan` (lib/allowlist, scanner, report) + `/api/health`, Vercel serverless, real header/HTTPS/exposed-file/login-defence scan, rate limit 10/min, audit log | Stateless, no DB, no queue, no WS, no terminal, no filesystem, no browser, ~10s Vercel function timeout, no task persistence |
| CLI scaffold | `~/workspace/cyber-agent/` Python planner stub, allowlist, scan stub, Dockerfile (not run) | No execution runtime, no agent loop, no verification |
| Cloud | None | No GCP/Railway account connected, no Postgres, Redis, S3, Docker in this VM, no secrets manager |

## 2. Root cause analysis
- Gemini refuses / gives generic advice because the prompt is sent to the model with no tool results and with trigger words ("hacking"). Fixed in v0.3 by sending full scan JSON + sanitised wording + refusal fallback to tool results.
- Replies are slow because the old fallback tried 6 models x 2 attempts. Fixed in v0.3 (max 3, 20s timeout).
- Nothing is "autonomous" yet because there is no server-side runtime: the browser is the only executor, and Vercel serverless cannot hold a workspace, terminal, or long task.
- The AQ. key sent in chat returns 403 "unregistered callers" on the Studio surface; it is likely a Vertex Express key. It was NOT saved anywhere and must be rotated. New keys should be AIza... from AI Studio.

## 3. Proposed cloud infrastructure (this repo)
```
Browser (cyber.hammadgfx.online)
  -> Next.js frontend (Vercel, unchanged)
  -> FastAPI cloud backend (this repo, Cloud Run / Railway)
       -> Agent runtime (plan -> tool -> execute -> observe -> verify -> replan)
       -> Execution manager (isolated workspace per task, subprocess, timeouts, limits)
       -> Gemini provider abstraction (Studio first, Vertex fallback, model fallback)
       -> Task store (SQLite locally, Postgres via DATABASE_URL in cloud)
       -> WebSocket /ws/tasks/{id} for live steps
       -> /api/scan reuse via the existing Next.js scan, or a Python scan module later
  -> Postgres (Cloud SQL / Railway Postgres, free tier)
  -> Redis (optional queue, free tier) - tasks currently run as asyncio jobs; Redis
     is added when concurrent tasks exceed one container.
  -> Object storage (GCS / S3-compatible, for workspace checkpoints)
  -> Separate executor service/VM for Docker + Playwright (Cloud Run does NOT
     allow privileged Docker-in-Docker; do not put the executor inside the API).
```
## 4. Estimated resources (experimental, scale-to-zero)
- Cloud Run API: 1 vCPU / 512MB, min instances 0, ~$0 idle, ~$5-15/mo light use
- Railway (alternative, simpler): Hobby $5/mo, Postgres $5/mo, free trial credits first
- Postgres: Cloud SQL free tier is limited; Railway Postgres or Neon free tier is cheaper to start
- Storage: GCS free tier 5GB, or local volume in dev
- Gemini: free tier, rate-limited; paid only if quota is hit
- Executor VM: on-demand only, e2-micro free tier on GCP, auto-shutdown after idle
- Total to start: $0-10/mo on free tiers, with a hard spending cap + billing alert (set in GCP/Railway, not in code).

## 5. Deployment plan
1. Create GitHub repo `cyber-agent-cloud` from this folder (no secrets in it).
2. Deploy API to Cloud Run: `gcloud run deploy cyber-agent --source . --set-env-vars GEMINI_API_KEY=...` (key from Secret Manager, never in chat/repo) OR Railway: connect repo, set env vars, deploy.
3. Set `NEXT_PUBLIC_CLOUD_API_URL` in the Vercel frontend, add a "Cloud tasks" panel that calls `/tasks` + WebSocket.
4. Add Postgres (DATABASE_URL) and object storage when the first persistent project is saved.
5. Add the separate executor service only when Docker/Playwright tasks are needed.
6. Run `test_workspace_e2e.py` + `test_e2e.py` after each deploy; never claim a deploy works without a live `/health` check.

## 6. What is real vs not yet real
- REAL and tested: workspace create/write/run/fix/verify (test_workspace_e2e.py PASS), FastAPI health, task create/get/cancel, honest failure when GEMINI_API_KEY is missing, scan backend v0.3.
- NOT yet real: cloud deployment (no GCP/Railway account connected yet), Postgres/Redis/S3 wiring (code is env-ready, not provisioned), Playwright browser tool (returns an error until Playwright is installed in the executor), persistent task history across restarts (SQLite file, not Postgres yet).
