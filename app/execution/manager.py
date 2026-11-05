"""Isolated workspace per task. Real subprocess execution, with limits.
No Docker-in-Docker assumed: on Cloud Run this runs as a plain process
inside the service container; for full isolation deploy the executor as a
separate service / VM (see README + docker-compose)."""
import os, shutil, subprocess, time
from pathlib import Path
FORBIDDEN = ["rm -rf /", "rm -rf ~", "sudo ", "shutdown", "reboot", ":(){", "mkfs", "dd if="]
class Workspace:
    def __init__(self, base, task_id):
        self.root = (Path(base) / "workspaces" / task_id).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
    def write(self, rel, content):
        p = (self.root / rel).resolve()
        if not str(p).startswith(str(self.root)): raise ValueError("path escapes workspace")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p.relative_to(self.root))
    def read(self, rel):
        p = (self.root / rel).resolve()
        if not str(p).startswith(str(self.root)): raise ValueError("path escapes workspace")
        return p.read_text(encoding="utf-8")
    def list_files(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file())
    def run(self, cmd, timeout=30):
        if any(f in cmd for f in FORBIDDEN): raise ValueError(f"forbidden command: {cmd}")
        t0 = time.time()
        r = subprocess.run(cmd, shell=True, cwd=self.root, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": r.returncode, "stdout": r.stdout[-4000:], "stderr": r.stderr[-4000:], "took_s": round(time.time()-t0, 2)}
    def size_mb(self):
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file()) / 1024 / 1024
    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)
