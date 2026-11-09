"""File attachments for tasks (v0.6): validate, store and read user-uploaded
files so the agent can answer based on their content.

Security rules (never relaxed):
- Extension allowlist + magic-byte check: a renamed .exe/.zip is still
  rejected. Archives and executables are never accepted.
- Files are stored ONLY inside the task's isolated workspace (uploads/)
  and are never served back publicly and never executed.
- Text/PDF content is injected into the prompt capped (~20 KB per file).
- Images go to Gemini as inlineData parts (PNG/JPEG/WebP only; GIF is
  stored but NOT sent inline - the Gemini REST API does not document GIF
  inlineData, so a GIF would risk failing the whole call).
- Total image payload sent to Gemini is capped (~18 MB); images over the
  budget are listed in the prompt but not sent, with a note saying so.
"""
import base64
import os
import re

MAX_FILE_BYTES = 10 * 1024 * 1024          # 10 MB per file
MAX_FILES = 5                               # per task
TEXT_INJECT_CHARS = 20_000                  # per file, into the prompt
IMAGE_BUDGET_BYTES = 18_000_000             # total inlineData per Gemini call

# kind -> (extensions, mime for Gemini inlineData or None)
IMAGE_EXTS = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
              "webp": "image/webp", "gif": "image/gif"}
PDF_EXTS = {"pdf"}
TEXT_EXTS = {"txt", "md", "csv", "json", "py", "js", "ts", "html", "css"}


def _magic_ok(kind, data: bytes) -> bool:
    """Magic-byte check so a renamed executable/archive cannot sneak in."""
    if kind == "image":
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return True
        if data[:3] == b"\xff\xd8\xff":
            return True
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return True
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return True
        return False
    if kind == "pdf":
        return data[:5] == b"%PDF-"
    # text: must decode as UTF-8 (a binary blob in a .txt is not text).
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def classify(filename: str):
    """Returns (kind, mime) or (None, None) for a disallowed extension."""
    ext = (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    if ext in IMAGE_EXTS:
        return "image", IMAGE_EXTS[ext]
    if ext in PDF_EXTS:
        return "pdf", "application/pdf"
    if ext in TEXT_EXTS:
        return "text", "text/plain"
    return None, None


def sanitize_filename(name: str) -> str:
    """Strip directories, control chars and separators; never empty."""
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = name.strip(". ")
    if not name or name in (".", ".."):
        name = "file"
    return name[:120]


def validate_upload(filename: str, data: bytes):
    """Returns (meta_dict, error_string). meta has name/size/kind/mime.
    error is None when the file is acceptable."""
    name = sanitize_filename(filename)
    if len(data) > MAX_FILE_BYTES:
        return None, f"File {name} is too large ({len(data) / 1024 / 1024:.1f} MB > 10 MB)."
    kind, mime = classify(name)
    if kind is None:
        return None, (f"File type not allowed: {name}. Allowed: images "
                      "(png, jpg, jpeg, webp, gif), PDF, and text docs "
                      "(txt, md, csv, json, py, js, ts, html, css).")
    if not data:
        return None, f"File {name} is empty."
    if not _magic_ok(kind, data):
        return None, (f"File {name} does not look like a real {kind} file "
                      "(contents do not match its extension).")
    return {"name": name, "size": len(data), "kind": kind, "mime": mime}, None


def extract_text(kind: str, data: bytes, name: str) -> str:
    """Extract readable text from a text doc or a PDF, capped. Never raises:
    on failure returns a short note the agent can report."""
    if kind == "text":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return f"[NOTE: {name} could not be read as text.]"
    elif kind == "pdf":
        try:
            from pypdf import PdfReader
            import io
            reader = PdfReader(io.BytesIO(data))
            parts = []
            for page in reader.pages:
                try:
                    parts.append(page.extract_text() or "")
                except Exception:
                    continue
            text = "\n".join(parts)
            if not text.strip():
                return (f"[NOTE: {name} is a PDF with no extractable text "
                        "(it may be scanned images).]")
        except Exception as e:
            return f"[NOTE: {name} could not be read as a PDF ({e}).]"
    else:
        return ""
    if len(text) > TEXT_INJECT_CHARS:
        text = text[:TEXT_INJECT_CHARS] + f"\n[NOTE: {name} truncated to {TEXT_INJECT_CHARS} characters.]"
    return text


def build_attachment_context(files_meta, read_bytes):
    """Build what the agent sees for its attachments.

    files_meta: list of {name, size, kind, mime, rel} (rel = path inside
    the task workspace, e.g. "uploads/photo.png").
    read_bytes: callable(rel) -> bytes, for reading the stored files.
    Returns (prompt_block: str, images: [(mime, base64_str)]).
    Images are PNG/JPEG/WebP only, within the total budget; anything
    over budget is listed with a note instead of being sent.
    """
    lines = ["Attached files (in your workspace under uploads/):"]
    images = []
    budget_left = IMAGE_BUDGET_BYTES
    for meta in files_meta:
        rel = meta["rel"]
        if meta["kind"] == "text" or meta["kind"] == "pdf":
            try:
                data = read_bytes(rel)
                text = extract_text(meta["kind"], data, meta["name"])
            except Exception as e:
                text = f"[NOTE: {meta['name']} could not be read ({e}).]"
            lines.append(f"\n--- file: {meta['name']} ({meta['kind']}, "
                         f"{meta['size']} bytes) ---\n{text}")
        elif meta["kind"] == "image":
            if meta["mime"] in ("image/png", "image/jpeg", "image/webp") and meta["size"] <= budget_left:
                try:
                    data = read_bytes(rel)
                    images.append((meta["mime"], base64.b64encode(data).decode()))
                    budget_left -= meta["size"]
                    lines.append(f"\n--- file: {meta['name']} (image, "
                                 f"{meta['size']} bytes) --- [image sent to "
                                 "you with this prompt — look at it and "
                                 "answer based on what it shows]")
                except Exception as e:
                    lines.append(f"\n--- file: {meta['name']} (image) --- "
                                 f"[NOTE: could not be read ({e}).]")
            elif meta["mime"] == "image/gif":
                lines.append(f"\n--- file: {meta['name']} (GIF image, "
                             f"{meta['size']} bytes) --- [NOTE: GIF images "
                             "cannot be shown inline; answer from the "
                             "filename and the user's prompt.]")
            else:
                lines.append(f"\n--- file: {meta['name']} (image, "
                             f"{meta['size']} bytes) --- [NOTE: image not "
                             "sent (over the per-task image budget); answer "
                             "from the filename and the user's prompt.]")
    return "\n".join(lines), images
