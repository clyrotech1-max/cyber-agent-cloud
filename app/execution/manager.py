"""Isolated workspace per task. Real subprocess execution, with limits.
No Docker-in-Docker assumed: on Cloud Run this runs as a plain process
inside the service container; for full isolation deploy the executor as a
separate service / VM (see README + docker-compose).

Shell hardening (v0.5, P0): commands run with shell=False via shlex.split,
only an allowlist of read-only inspection binaries may run - no python,
no node, no shell, no curl/wget, no network tools. The agent can write
files and inspect them (cat/grep/ls) but cannot execute code in this
sandbox. Shell metacharacters and env-var expansion are rejected outright.
"""
import os, shlex, shutil, subprocess, time
from pathlib import Path
FORBIDDEN = ["rm -rf /", "rm -rf ~", "sudo ", "shutdown", "reboot", ":(){", "mkfs", "dd if="]
# Read-only inspection binaries only. Anything else (python3, node, sh,
# bash, curl, wget, nc, ...) is refused - the agent must not execute code.
ALLOWED_BINARIES = {"ls", "cat", "head", "tail", "grep", "rg", "wc", "find", "pwd", "echo"}
# Shell metacharacters / operators: with shell=False these are inert, but
# they are rejected anyway so a prompt-injected command chain fails loudly
# instead of silently running as a literal argument.
_SHELL_META = set(";|&><$`\n\r")
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
        if not isinstance(cmd, str) or not cmd.strip():
            raise ValueError("empty command")
        if any(f in cmd for f in FORBIDDEN): raise ValueError(f"forbidden command: {cmd}")
        # Reject shell operators, redirection, pipes, $() / $VAR expansion,
        # backticks and embedded newlines before any parsing happens.
        hit = [c for c in cmd if c in _SHELL_META]
        if hit:
            raise ValueError(f"command not allowed (shell metacharacter {sorted(set(hit))!r}): {cmd}")
        try:
            argv = shlex.split(cmd)
        except ValueError as e:
            raise ValueError(f"command not allowed (cannot parse): {e}")
        if not argv:
            raise ValueError("empty command")
        binary = argv[0].split("/")[-1]
        if binary not in ALLOWED_BINARIES:
            raise ValueError(f"command not allowed: {binary!r} is not in the allowed list ({', '.join(sorted(ALLOWED_BINARIES))})")
        # Stripped environment: only PATH, HOME, LANG reach the child.
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        t0 = time.time()
        r = subprocess.run(argv, shell=False, cwd=self.root, capture_output=True, text=True, timeout=timeout, env=env)
        return {"cmd": cmd, "returncode": r.returncode, "stdout": r.stdout[-4000:], "stderr": r.stderr[-4000:], "took_s": round(time.time()-t0, 2)}
    def size_mb(self):
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file()) / 1024 / 1024
    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)
