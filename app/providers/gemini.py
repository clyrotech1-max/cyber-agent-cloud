"""Gemini provider abstraction. No hardcoded success: a failed call raises."""
import httpx, json
# REST loop models only. gemini-3.8-live is NOT here on purpose: Google returns
# HTTP 400 "only supports real-time bidirectional streaming via WebSocket
# (bidiGenerateContent)" - it can never answer a REST generateContent call.
# Its proper home is a Live API WebSocket session (fast chat), not this loop.
# Aliases (gemini-flash-latest) and retired models (2.5-flash) removed.
# Flash-Lite added as quota fallback: 3.8-flash keeps hitting free-tier 429, and
# Flash-Lite's free daily allowance is reported far higher. gemini-3.5-flash-lite
# is stable/GA (21 Jul 2026, no shutdown announced); gemini-3.8-flash-lite is
# unverified (not in Google's catalog) - tried after it, a 404 just falls through.
MODELS = ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.8-flash-lite", "gemini-3-flash-preview"]
class GeminiProvider:
    def __init__(self, api_key, model="gemini-3.8-flash"):
        self.key = api_key; self.model = model
    async def generate(self, prompt, timeout=20):
        if not self.key:
            raise RuntimeError("GEMINI_API_KEY not set - set it in the cloud backend env, never in chat/repo")
        errors = {}
        for m in dict.fromkeys(MODELS + [self.model]):
            try:
                async with httpx.AsyncClient(timeout=timeout) as c:
                    r = await c.post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                        headers={"Content-Type": "application/json", "x-goog-api-key": self.key},
                        json={"contents": [{"parts": [{"text": prompt}]}]})
                    j = r.json()
                    text = "".join(p.get("text", "") for p in j.get("candidates", [{}])[0].get("content", {}).get("parts", []))
                    if r.status_code == 200 and text: return text, m
                    err = str(j.get("error", {}).get("message", r.status_code))
                    errors[m] = f"HTTP {r.status_code}: {err[:160]}"
                    if "API key not valid" in err: raise RuntimeError(f"Gemini key invalid: {err}")
            except RuntimeError: raise
            except Exception as e: errors[m] = f"EXC {type(e).__name__}: {str(e)[:160]}"
        raise RuntimeError("Gemini failed on all models: " + " | ".join(f"{m} -> {str(e)[:250]}" for m, e in errors.items())[:1500])
