"""Defensive scanner - read-only probes only. Python port of the web lib/scanner.js.
No login attempts, no password guessing, no form submission, no exploitation.
Only public HTTP responses."""
import os, re, httpx
from datetime import datetime, timezone

UA = {"User-Agent": "CyberAgent-Cloud/0.3 (defensive-security-check)"}
# Proxy explicitly from env (never log it). trust_env=False avoids httpx choking
# on malformed NO_PROXY entries like "[::1]". On Render there is no proxy env.
_PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or None
def _client(**kw):
    return httpx.AsyncClient(trust_env=False, proxy=_PROXY, headers=UA, **kw)

async def _probe(client, url, timeout=8.0):
    try:
        r = await client.get(url, timeout=timeout)
        body = ""
        try:
            body = (r.text or "")[:4000]
        except Exception:
            body = ""
        return {"status": r.status_code, "location": r.headers.get("location", ""), "server": r.headers.get("server", ""), "poweredBy": r.headers.get("x-powered-by", ""), "body": body}
    except Exception as e:
        return {"status": 0, "error": str(e)[:120]}

async def run_full_scan(host: str):
    url = f"https://{host}/"
    async with _client( follow_redirects=True, timeout=15.0) as client:
        res = await client.get(url)
        headers = {}
        for h in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "server", "x-powered-by"]:
            headers[h] = res.headers.get(h) or "MISSING"
        html = res.text or ""
        findings = []
        def add(sev, text):
            findings.append({"severity": sev, "text": text})
        if headers["strict-transport-security"] == "MISSING":
            add("medium", "Strict-Transport-Security MISSING - MITM risk on HTTP, add HSTS max-age=31536000; includeSubDomains")
        else:
            add("ok", f"Strict-Transport-Security PRESENT: {headers['strict-transport-security']}")
        if headers["content-security-policy"] == "MISSING":
            add("medium", "Content-Security-Policy MISSING - XSS / injection risk, add CSP")
        else:
            add("ok", "Content-Security-Policy PRESENT")
        if headers["x-frame-options"] == "MISSING":
            add("low", "X-Frame-Options MISSING - clickjacking risk, add DENY or SAMEORIGIN")
        else:
            add("ok", f"X-Frame-Options PRESENT: {headers['x-frame-options']}")
        if headers["x-content-type-options"] == "MISSING":
            add("low", "X-Content-Type-Options MISSING - add nosniff")
        else:
            add("ok", "X-Content-Type-Options PRESENT")
        if headers["referrer-policy"] == "MISSING":
            add("low", "Referrer-Policy MISSING - add strict-origin-when-cross-origin")
        else:
            add("ok", "Referrer-Policy PRESENT")
        if headers["server"] != "MISSING":
            add("low", f"Server header leaks version info: {headers['server']} - hide server version")
        if headers["x-powered-by"] != "MISSING":
            add("low", f"X-Powered-By leaks stack: {headers['x-powered-by']} - remove this header")
        gen = re.search(r"<meta[^>]*name=[\"']generator[\"'][^>]*>", html, re.I)
        if gen:
            add("low", f"Generator meta tag leaks CMS/version: {gen.group(0)[:120]}")
        tech = []
        if re.search(r"wp-content|wp-includes", html, re.I):
            tech.append("WordPress")
            add("info", "WordPress detected in HTML - keep WP + plugins updated, remove unused plugins")
        if re.search(r"next/|_next/", html):
            tech.append("Next.js")
        async with _client( follow_redirects=False, timeout=8.0) as c2:
            http_probe = await _probe(c2, f"http://{host}/", 4.0)
        https_redirect = 300 <= (http_probe.get("status") or 0) < 400 and "https:" in (http_probe.get("location") or "").lower()
        if https_redirect:
            add("ok", f"HTTP redirects to HTTPS ({http_probe['status']} -> {http_probe['location']})")
        else:
            add("medium", f"HTTP does NOT redirect to HTTPS (status {http_probe.get('status')}) - force HTTPS redirect")
        exposed_paths = ["/.env", "/.git/HEAD", "/robots.txt", "/security.txt", "/.well-known/security.txt", "/wp-login.php", "/admin"]
        async with _client( follow_redirects=False, timeout=8.0) as c3:
            import asyncio
            exposed_res = await asyncio.gather(*[_probe(c3, f"https://{host}{p}", 5.0) for p in exposed_paths])
        exposed_files = [{"path": p, "status": r.get("status") or 0} for p, r in zip(exposed_paths, exposed_res)]
        env_public = any(e["path"] == "/.env" and e["status"] == 200 for e in exposed_files)
        git_public = any(e["path"] == "/.git/HEAD" and e["status"] == 200 for e in exposed_files)
        if env_public:
            add("high", "CRITICAL: /.env is publicly reachable (200) - secrets may leak, block it immediately")
        if git_public:
            add("high", "HIGH: /.git/HEAD is publicly reachable (200) - source history may leak, block .git")
        async with _client( follow_redirects=False, timeout=8.0) as c4:
            import asyncio
            login_res = await asyncio.gather(*[_probe(c4, f"https://{host}{p}", 5.0) for p in ["/wp-login.php", "/login", "/admin/login"]])
        login_page = ""
        for p, r in zip(["/wp-login.php", "/login", "/admin/login"], login_res):
            if r.get("status") == 200:
                login_page = p
                break
        if login_page:
            async with _client( follow_redirects=False, timeout=8.0) as c5:
                lp = await _probe(c5, f"https://{host}{login_page}", 5.0)
            body = lp.get("body") or ""
            has_captcha = bool(re.search(r"captcha|recaptcha|hcaptcha", body, re.I))
            has_2fa = bool(re.search(r"two.factor|2fa|otp|authenticator", body, re.I))
            add("info", f"Login page found at {login_page} - password guessing was NOT done. Defence check: captcha {'FOUND' if has_captcha else 'NOT seen'}, 2FA mention {'FOUND' if has_2fa else 'NOT seen'}. Fix: rate-limit 5 attempts/minute, lockout after 5 fails, MFA on admin, captcha on login.")
        else:
            add("info", "No common login page found at /wp-login.php, /login, /admin/login - if login exists elsewhere, check its rate-limit + MFA there.")
        counts = {"high": 0, "medium": 0, "low": 0, "ok": 0, "info": 0}
        for f in findings:
            if f["severity"] in counts:
                counts[f["severity"]] += 1
        return {
            "url": url, "status": res.status_code, "https": True, "httpsRedirect": https_redirect,
            "headers": headers, "tech": tech,
            "exposedFiles": [f"{e['path']} -> {e['status'] or 'no response'}" for e in exposed_files],
            "loginPage": login_page or "not found",
            "findings": [f"[{f['severity'].upper()}] {f['text']}" for f in findings],
            "severityCounts": counts,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
        }

def build_report(scan, target):
    c = scan.get("severityCounts") or {}
    lines = [
        f"# Cyber Agent Scan Report - {target}", "",
        f"Scanned: {scan.get('scannedAt') or ''} | URL: {scan.get('url')} | HTTP: {scan.get('status')}",
        f"Severity: HIGH {c.get('high', 0)} | MEDIUM {c.get('medium', 0)} | LOW {c.get('low', 0)} | OK {c.get('ok', 0)}", "",
        "## Findings",
        *[f"- {f}" for f in (scan.get("findings") or [])], "",
        "## Exposed files (read-only status check)",
        *[f"- {f}" for f in (scan.get("exposedFiles") or [])], "",
        "## Login defence",
        f"- Login page: {scan.get('loginPage') or 'not found'} - password guessing was NOT done, only the defence check above.", "",
        "## What was NOT tested",
        "- No password guessing / brute-force login attempts, no SQLi / XSS payloads, no form submission. Those need a separate authorised penetration test with written scope.",
    ]
    return "\n".join(lines)
