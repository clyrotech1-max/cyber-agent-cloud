"""v0.6 tests: file attachments — multipart upload, validation, PDF text
extraction, image inlineData to Gemini, workspace storage, FILES prompt
section, guest rejection, JSON body still works.

Run:  .venv/bin/python test_v06.py
Uses a throwaway DATA_DIR (/tmp/cybnet-v06-test-data) - never the real data/.
No real Gemini key is needed: the runtime tests stub the LLM
(monkeypatched generate) to prove images + injected text reach the model.
"""
import asyncio
import base64
import io
import json
import os
import shutil
import sys

DATA_DIR = "/tmp/cybnet-v06-test-data"
shutil.rmtree(DATA_DIR, ignore_errors=True)
os.environ["DATA_DIR"] = DATA_DIR
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import auth as authmod  # noqa: E402
from app.config import settings  # noqa: E402
from app.agent.runtime import AgentRuntime, SYSTEM  # noqa: E402
from app.attachments import (  # noqa: E402
    validate_upload, classify, sanitize_filename, extract_text,
    build_attachment_context, MAX_FILES)
import app.main as mainmod  # noqa: E402

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


# ------------------------------------------------------------------ fixtures
# 1x1 red PNG.
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
# 1x1 GIF.
GIF_1X1 = base64.b64decode("R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")


def make_pdf(text):
    """Minimal valid one-page PDF with the given text (pypdf-readable)."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    stream = ("BT /F1 24 Tf 100 700 Td (" + text + ") Tj ET").encode()
    objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n").encode()
    return bytes(out)


PDF_HELLO = make_pdf("Hello PDF Avin")


def _client_and_user(email="v06-user@example.com"):
    """Fresh TestClient + a registered user token. Returns (client, headers)."""
    from fastapi.testclient import TestClient
    mainmod._task_hits.clear()
    c = TestClient(mainmod.app)
    reg = c.post("/auth/register",
                 json={"email": email, "password": "testpass123"})
    assert reg.status_code == 200, reg.text
    tok = reg.json()["token"]
    return c, {"Authorization": f"Bearer {tok}"}


def _xip(n):
    """Unique X-Forwarded-For IP per create, so the v0.5 rate limiter
    (3/min/IP) never trips inside these tests."""
    return {"X-Forwarded-For": f"203.0.113.{n}"}


# ------------------------------------------------------- validation (unit)
def test_validation():
    meta, err = validate_upload("notes.txt", b"hello world")
    check("txt accepted as text", meta and meta["kind"] == "text" and err is None, str(err))
    meta, err = validate_upload("photo.png", PNG_1X1)
    check("png accepted as image", meta and meta["kind"] == "image" and meta["mime"] == "image/png", str(err))
    meta, err = validate_upload("doc.pdf", PDF_HELLO)
    check("pdf accepted", meta and meta["kind"] == "pdf" and err is None, str(err))
    meta, err = validate_upload("run.exe", b"MZ" + b"\x00" * 100)
    check("exe rejected", meta is None and "not allowed" in (err or ""), str(err))
    meta, err = validate_upload("a.zip", b"PK\x03\x04" + b"\x00" * 100)
    check("zip rejected", meta is None and "not allowed" in (err or ""), str(err))
    meta, err = validate_upload("script.sh", b"#!/bin/sh\necho hi\n")
    check("sh rejected", meta is None and "not allowed" in (err or ""), str(err))
    meta, err = validate_upload("fake.png", b"MZ" + b"\x00" * 100)
    check("renamed exe as png rejected by magic bytes",
          meta is None and "does not look like" in (err or ""), str(err))
    meta, err = validate_upload("empty.txt", b"")
    check("empty file rejected", meta is None and "empty" in (err or ""), str(err))
    meta, err = validate_upload("big.txt", b"x" * (10 * 1024 * 1024 + 1))
    check("file over 10 MB rejected", meta is None and "too large" in (err or ""), str(err))
    check("classify unknown ext -> None", classify("x.tar.gz") == (None, None))
    check("sanitize strips directories", sanitize_filename("a/b/c.txt") == "c.txt")
    check("sanitize dotdot -> file", sanitize_filename("..") == "file")
    check("extract_text on txt", "hello" in extract_text("text", b"hello world", "a.txt"))
    check("extract_text on pdf", "Hello PDF Avin" in extract_text("pdf", PDF_HELLO, "d.pdf"),
          extract_text("pdf", PDF_HELLO, "d.pdf")[:80])


# ------------------------------------------------------------ endpoint: upload
def test_multipart_upload_ok():
    c, hdr = _client_and_user("v06-ok@example.com")
    files = [
        ("files", ("notes.txt", b"SECRET_MARKER_TXT_77", "text/plain")),
        ("files", ("doc.pdf", PDF_HELLO, "application/pdf")),
        ("files", ("pic.png", PNG_1X1, "image/png")),
    ]
    h = dict(hdr); h.update(_xip(1))
    r = c.post("/tasks", data={"prompt": "Summarise my files"},
               files=files, headers=h)
    check("multipart create 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
    body = r.json()
    got = body.get("files", [])
    check("response lists 3 files",
          len(got) == 3, json.dumps(got)[:200])
    check("response file kinds",
          [g["kind"] for g in got] == ["text", "pdf", "image"], str(got))
    check("response file names",
          [g["name"] for g in got] == ["notes.txt", "doc.pdf", "pic.png"], str(got))
    tid = body.get("task_id")
    ws = os.path.join(DATA_DIR, "workspaces", tid, "uploads")
    check("files on disk under uploads/",
          tid and sorted(os.listdir(ws)) == ["doc.pdf", "notes.txt", "pic.png"],
          str(os.listdir(ws)) if tid and os.path.isdir(ws) else "no dir")
    check("uploaded png bytes intact",
          open(os.path.join(ws, "pic.png"), "rb").read() == PNG_1X1)
    c.delete("/auth/account", headers=hdr)


def test_multipart_rejections():
    c, hdr = _client_and_user("v06-rej@example.com")
    h = dict(hdr); h.update(_xip(2))
    r = c.post("/tasks", data={"prompt": "x"},
               files=[("files", ("evil.exe", b"MZ" + b"\x00" * 50, "application/octet-stream"))],
               headers=h)
    check("exe upload -> 400", r.status_code == 400, f"{r.status_code} {r.text[:120]}")
    check("rejected file leaves no task row",
          "evil" not in r.text or r.status_code == 400)
    h = dict(hdr); h.update(_xip(3))
    r = c.post("/tasks", data={"prompt": "x"},
               files=[("files", ("big.txt", b"x" * (10 * 1024 * 1024 + 1), "text/plain"))],
               headers=h)
    check("oversize upload -> 400", r.status_code == 400, f"{r.status_code}")
    h = dict(hdr); h.update(_xip(4))
    many = [("files", (f"f{i}.txt", b"hi", "text/plain")) for i in range(MAX_FILES + 1)]
    r = c.post("/tasks", data={"prompt": "x"}, files=many, headers=h)
    check("6 files -> 400", r.status_code == 400, f"{r.status_code} {r.text[:120]}")
    h = dict(hdr); h.update(_xip(5))
    r = c.post("/tasks", data={"prompt": "x"}, files=[], headers=h)
    check("multipart with no files still creates task",
          r.status_code == 200 and r.json().get("files") == [], f"{r.status_code} {r.text[:120]}")
    h = dict(hdr); h.update(_xip(6))
    r = c.post("/tasks", data={"prompt": ""},
               files=[("files", ("a.txt", b"hi", "text/plain"))], headers=h)
    check("empty prompt multipart -> 400", r.status_code == 400, f"{r.status_code}")
    c.delete("/auth/account", headers=hdr)


def test_guest_cannot_upload():
    from fastapi.testclient import TestClient
    mainmod._task_hits.clear()
    c = TestClient(mainmod.app)
    r = c.post("/tasks", data={"prompt": "read this"},
               files=[("files", ("a.txt", b"hi", "text/plain"))],
               headers=_xip(7))
    check("guest multipart with files -> 401",
          r.status_code == 401, f"{r.status_code} {r.text[:120]}")


def test_json_still_works():
    c, hdr = _client_and_user("v06-json@example.com")
    h = dict(hdr); h.update(_xip(8))
    r = c.post("/tasks", json={"prompt": "Hello Avin"}, headers=h)
    check("JSON create 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
    check("JSON create has empty files list",
          r.json().get("files") == [], str(r.json()))
    check("JSON create has task_id", bool(r.json().get("task_id")))
    c.delete("/auth/account", headers=hdr)


def test_duplicate_filenames():
    c, hdr = _client_and_user("v06-dup@example.com")
    h = dict(hdr); h.update(_xip(9))
    files = [("files", ("a.txt", b"first", "text/plain")),
             ("files", ("a.txt", b"second", "text/plain"))]
    r = c.post("/tasks", data={"prompt": "dup names"}, files=files, headers=h)
    check("duplicate names create 200", r.status_code == 200, f"{r.status_code}")
    names = [g["name"] for g in r.json().get("files", [])]
    check("duplicate names de-duplicated",
          len(names) == 2 and len(set(names)) == 2, str(names))
    tid = r.json().get("task_id")
    ws = os.path.join(DATA_DIR, "workspaces", tid, "uploads")
    check("both duplicate files on disk",
          sorted(os.listdir(ws)) == sorted(names), str(os.listdir(ws)))
    c.delete("/auth/account", headers=hdr)


# ------------------------------------------------------- runtime: agent sees files
async def _run_with_stub(rt, script):
    """Stub provider: answers from `script` (list of JSON tool calls).
    Returns (runtime, captured_generate_calls)."""
    calls = []

    async def fake_generate(prompt, timeout=20, images=None):
        calls.append({"prompt": prompt, "images": images})
        if not script:
            return json.dumps({"plan": "done", "tool": "finish",
                               "args": {"result": "done"}, "verify": "n/a"}), "stub-model"
        return script.pop(0), "stub-model"

    rt.provider.generate = fake_generate
    out = await rt.run()
    return out, calls


async def test_text_and_pdf_injected():
    rt = AgentRuntime(settings, "v06-t1", "Summarise my files",
                      authed=True, user_id=None)
    rt.ws.write_bytes("uploads/notes.txt", b"SECRET_MARKER_TXT_77 is in the notes.")
    rt.ws.write_bytes("uploads/doc.pdf", PDF_HELLO)
    rt.attach_files([
        {"name": "notes.txt", "size": 36, "kind": "text", "mime": "text/plain",
         "rel": "uploads/notes.txt"},
        {"name": "doc.pdf", "size": len(PDF_HELLO), "kind": "pdf",
         "mime": "application/pdf", "rel": "uploads/doc.pdf"},
    ])
    out, calls = await _run_with_stub(rt, [])
    check("text content injected into model prompt",
          calls and "SECRET_MARKER_TXT_77" in calls[0]["prompt"],
          str(calls[0]["prompt"][:200]) if calls else "no calls")
    check("PDF text injected into model prompt",
          calls and "Hello PDF Avin" in calls[0]["prompt"],
          "missing PDF text")
    check("no images sent for text/pdf task",
          calls and calls[0]["images"] in (None, []), str(calls[0].get("images")))


async def test_image_parts_reach_provider():
    rt = AgentRuntime(settings, "v06-t2", "What is in this image?",
                      authed=True, user_id=None)
    rt.ws.write_bytes("uploads/pic.png", PNG_1X1)
    rt.attach_files([
        {"name": "pic.png", "size": len(PNG_1X1), "kind": "image",
         "mime": "image/png", "rel": "uploads/pic.png"},
    ])
    out, calls = await _run_with_stub(rt, [])
    check("image sent on first model call",
          calls and calls[0]["images"] is not None and len(calls[0]["images"]) == 1,
          str(calls[0].get("images"))[:80] if calls else "no calls")
    if calls and calls[0]["images"]:
        mime, b64 = calls[0]["images"][0]
        check("image mime is image/png", mime == "image/png", mime)
        check("image bytes round-trip",
              base64.b64decode(b64) == PNG_1X1)
    check("task result lists attachments",
          out.get("attachments") and out["attachments"][0]["name"] == "pic.png",
          str(out.get("attachments")))


async def test_gif_not_sent_inline():
    rt = AgentRuntime(settings, "v06-t3", "What is this gif?",
                      authed=True, user_id=None)
    rt.ws.write_bytes("uploads/a.gif", GIF_1X1)
    rt.attach_files([
        {"name": "a.gif", "size": len(GIF_1X1), "kind": "image",
         "mime": "image/gif", "rel": "uploads/a.gif"},
    ])
    out, calls = await _run_with_stub(rt, [])
    check("GIF not sent as inlineData",
          calls and calls[0]["images"] in (None, []), str(calls[0].get("images")))
    check("GIF note in prompt",
          calls and "cannot be shown inline" in calls[0]["prompt"],
          "missing GIF note")


async def test_agent_reads_upload_via_tools():
    # Stubbed LLM: list_files, then read_file, then finish. Proves the
    # agent can re-check uploads itself with its normal tools.
    script = [
        json.dumps({"plan": "list", "tool": "list_files", "args": {}, "verify": "n/a"}),
        json.dumps({"plan": "read", "tool": "read_file",
                    "args": {"path": "uploads/notes.txt"}, "verify": "n/a"}),
        json.dumps({"plan": "done", "tool": "finish",
                    "args": {"result": "read it: SECRET_MARKER_TXT_77"}, "verify": "n/a"}),
    ]
    rt = AgentRuntime(settings, "v06-t4", "Read my file",
                      authed=True, user_id=None)
    rt.ws.write_bytes("uploads/notes.txt", b"SECRET_MARKER_TXT_77 is in the notes.")
    rt.attach_files([
        {"name": "notes.txt", "size": 36, "kind": "text", "mime": "text/plain",
         "rel": "uploads/notes.txt"},
    ])
    out, calls = await _run_with_stub(rt, script)
    obs = " ".join(str(s.get("observation", "")) for s in out.get("steps", []))
    check("list_files shows uploads/notes.txt",
          "uploads/notes.txt" in obs, obs[:200])
    check("read_file returns the file content",
          "SECRET_MARKER_TXT_77" in obs, obs[:200])
    check("task completed", out.get("status") == "completed", str(out.get("status")))


async def test_text_cap():
    rt = AgentRuntime(settings, "v06-t5", "Summarise",
                      authed=True, user_id=None)
    big = b"x" * 25_000
    rt.ws.write_bytes("uploads/big.txt", big)
    rt.attach_files([
        {"name": "big.txt", "size": len(big), "kind": "text",
         "mime": "text/plain", "rel": "uploads/big.txt"},
    ])
    out, calls = await _run_with_stub(rt, [])
    check("long text truncated with note",
          calls and "truncated to 20000 characters" in calls[0]["prompt"],
          str(calls[0]["prompt"][-200:]) if calls else "no calls")


def test_system_files_section():
    check("SYSTEM has FILES section", "FILES - ATTACHED FILES" in SYSTEM)
    check("FILES section mentions uploads/",
          "uploads/" in SYSTEM)
    check("FILES section forbids executing uploads",
          "never execute an uploaded file" in SYSTEM)


async def main():
    test_validation()
    test_multipart_upload_ok()
    test_multipart_rejections()
    test_guest_cannot_upload()
    test_json_still_works()
    test_duplicate_filenames()
    await test_text_and_pdf_injected()
    await test_image_parts_reach_provider()
    await test_gif_not_sent_inline()
    await test_agent_reads_upload_via_tools()
    await test_text_cap()
    test_system_files_section()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)
    print("ALL v0.6 TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
