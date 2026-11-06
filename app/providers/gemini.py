"""Gemini provider abstraction. No hardcoded success: a failed call raises."""
import httpx, json
# gemini-3.8-live = Google's default low-latency model (GA 15 Sep 2026, Live API family).
# Tried first for fast response; 3.8-flash is the fallback workhorse.
# Aliases (gemini-flash-latest) and retired models (2.5-flash) removed - they silently swap/fail.
MODELS = ["gemini-3.8-live", "gemini-3.8-flash", "gemini-3-flash-preview"]
class GeminiProvider:
    def __init__(self, api_key, model="gemini-3.8-live"):
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
            except Exception as e: errors[m] = f"EXC: {str(e)[:160]}"
        raise RuntimeError("Gemini failed on all models: " + " | ".join(f"{m} -> {e}" for m, e in errors.items())[:1200])
