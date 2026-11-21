"""Checks a VEILUX backend the way a user meets it.

    python packaging/smoke_test.py dist/veilux-backend/veilux-backend
    python packaging/smoke_test.py python server.py

Starts the backend with a fresh data folder and a free port, then checks:
- its version and the pairing code it prints;
- pairing exchanges the code for the key, which is stored in the data folder,
  readable by this user only;
- requests need the key;
- local protection and indicator extraction work (no external service is
  called);
- a second copy on the same port explains itself and exits;
- the backend stops cleanly on Ctrl+C (Ctrl+Break on Windows);
- after a restart it keeps its key and shows a new pairing code.

Only the Python standard library is used, so it runs anywhere the packaged
backend runs.
"""
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# The version being released, as server.py states it.
VERSION = re.search(r'^VERSION = "([^"]+)"', (Path(__file__).resolve().parents[1] / "server.py").read_text(encoding="utf-8"), re.M).group(1)

WINDOWS = os.name == "nt"
SAMPLE = json.dumps({"user": "j.doe", "src_ip": "10.20.30.40", "dst_ip": "198.51.100.23",
                     "host": "ws-0042.corp.example.org", "event": "logon failure"})


class Backend:
    def __init__(self, command, port, data_dir):
        env = {k: v for k, v in os.environ.items() if not k.startswith("VEILUX_")}
        env.update(VEILUX_DATA_DIR=data_dir, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0
        self.process = subprocess.Popen([*command, "--port", str(port)], env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=flags)
        self.lines = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for raw in self.process.stdout:
            self.lines.append(raw.decode("utf-8", "replace").rstrip())

    @property
    def output(self):
        return "\n".join(self.lines)

    def wait_for(self, pattern, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            match = re.search(pattern, self.output)
            if match:
                return match
            if self.process.poll() is not None:
                self.reader.join(5)
                match = re.search(pattern, self.output)
                if match:
                    return match
                raise AssertionError(f"backend exited with {self.process.returncode}:\n{self.output}")
            time.sleep(0.2)
        raise AssertionError(f"no {pattern!r} after {seconds}s:\n{self.output}")

    def interrupt(self, sigterm=False):
        """What the analyst does in the console window: Ctrl+C (Ctrl+Break on
        Windows). With sigterm, what a service manager or `kill` does instead."""
        self.process.send_signal(signal.CTRL_BREAK_EVENT if WINDOWS else signal.SIGTERM if sigterm else signal.SIGINT)
        try:
            code = self.process.wait(30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            raise AssertionError("backend did not stop within 30 s of Ctrl+C:\n" + self.output)
        self.reader.join(5)
        return code


def request(port, path, body=None, key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if key:
        headers["X-Veilux-Token"] = key
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers,
                                 method="POST" if data is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def check(label, condition, detail=""):
    if not condition:
        raise AssertionError(f"{label} {detail}".strip())
    print(f"  PASS  {label}")


def main(command):
    version = subprocess.run([*command, "--version"], capture_output=True, text=True, timeout=120)
    check("--version", version.returncode == 0 and "VEILUX backend " + VERSION in version.stdout, version.stdout + version.stderr)
    with tempfile.TemporaryDirectory(prefix="veilux-smoke-") as root:
        data_dir = os.path.join(root, "VEILUX")          # the backend creates it
        port = free_port()
        backend = Backend(command, port, data_dir)
        try:
            code = backend.wait_for(r"Pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4})", 120).group(1)
            check("start-up shows a pairing code and the data folder", "Data folder: " + data_dir in backend.output)
            status, health = request(port, "/health")
            check("/health answers without the key", status == 200 and health.get("version") == VERSION, str(health))
            check("other requests need the key", request(port, "/lessons")[0] == 401)
            status, wrong = request(port, "/pair", {"code": "AAAA-AAAA" if code != "AAAA-AAAA" else "BBBB-BBBB"})
            check("a wrong pairing code is refused", status == 401, str(wrong))
            status, paired = request(port, "/pair", {"code": code.lower().replace("-", " ")})
            key = (paired or {}).get("token", "")
            check("pairing returns the backend key", status == 200 and len(key) >= 40, str(paired))
            check("the key is never printed", key not in backend.output)
            key_file = os.path.join(data_dir, "veilux_backend.key")
            with open(key_file, encoding="utf-8") as handle:
                check("the key is stored in the data folder", handle.read().strip() == key)
            if not WINDOWS:
                check("the data folder is private (0700)", stat.S_IMODE(os.stat(data_dir).st_mode) == 0o700,
                      oct(os.stat(data_dir).st_mode))
                check("the key file is private (0600)", stat.S_IMODE(os.stat(key_file).st_mode) == 0o600)
            check("the paired key is accepted", request(port, "/auth/check", key=key) == (200, {"paired": True}))
            status, protected = request(port, "/sanitize", {"logs": [SAMPLE]}, key)
            text = (protected or {}).get("sanitized_log", "")
            check("local protection replaces addresses, users and hosts",
                  status == 200 and "10.20.30.40" not in text and "j.doe" not in text and "⟦" in text, text[:300])
            status, found = request(port, "/indicators", {"logs": [SAMPLE]}, key)
            values = {item.get("value") for item in (found or {}).get("indicators", [])}
            check("indicators are listed", status == 200 and "198.51.100.23" in values, str(values))
            # The backend writes UTF-8; the Windows code page would not decode all of it.
            second = subprocess.run([*command, "--port", str(port)], capture_output=True, encoding="utf-8", errors="replace",
                                    timeout=120, stdin=subprocess.DEVNULL, env={**os.environ, "VEILUX_DATA_DIR": data_dir})
            check("a second copy on the same port explains itself", second.returncode == 1 and "already in use" in second.stderr,
                  second.stdout + second.stderr)
        finally:
            exit_code = backend.interrupt() if backend.process.poll() is None else backend.process.returncode
        check("Ctrl+C stops the backend cleanly", exit_code == 0 and "VEILUX backend stopped." in backend.output,
              f"exit {exit_code}\n{backend.output}")
        leftovers = [name for name in os.listdir(data_dir) if name.endswith(".tmp")]
        check("no temporary files are left behind", not leftovers, str(leftovers))

        restarted = Backend(command, port, data_dir)
        try:
            new_code = restarted.wait_for(r"Pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4})", 120).group(1)
            check("after a restart the key is kept", request(port, "/auth/check", key=key) == (200, {"paired": True}))
            check("after a restart a new pairing code is shown", new_code != code)
        finally:
            code = restarted.interrupt(sigterm=True)
            check("the restarted backend stops cleanly" + ("" if WINDOWS else " on SIGTERM"),
                  code == 0 and "VEILUX backend stopped." in restarted.output, f"exit {code}\n{restarted.output}")
    print("All smoke checks passed.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
