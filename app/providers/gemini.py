"""Gemini provider abstraction. No hardcoded success: a failed call raises."""
import httpx, json
MODELS = ["gemini-3.8-flash", "gemini-flash-latest", "gemini-3-flash-preview", "gemini-2.5-flash"]
class GeminiProvider:
    def __init__(self, api_key, model="gemini-flash-latest"):
        self.key = api_key; self.model = model
    async def generate(self, prompt, timeout=25):
        if not self.key:
            raise RuntimeError("GEMINI_API_KEY not set - set it in the cloud backend env, never in chat/repo")
        last = ""
        for m in dict.fromkeys([self.model] + MODELS):
            try:
                async with httpx.AsyncClient(timeout=timeout) as c:
                    r = await c.post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent",
                        headers={"Content-Type": "application/json", "x-goog-api-key": self.key},
                        json={"contents": [{"parts": [{"text": prompt}]}]})
                    j = r.json()
                    text = "".join(p.get("text", "") for p in j.get("candidates", [{}])[0].get("content", {}).get("parts", []))
                    if r.status_code == 200 and text: return text, m
                    last = str(j.get("error", {}).get("message", r.status_code))
                    if "API key not valid" in last: raise RuntimeError(f"Gemini key invalid: {last}")
            except RuntimeError: raise
            except Exception as e: last = str(e)
        raise RuntimeError(f"Gemini failed on all models, last error: {last[:200]}")
