"""Who may call the backend: only the paired VEILUX extension.

Web pages are refused by origin and host checks. Other browser extensions, and
other programs, are refused because every request needs the backend key, which
only the paired extension holds."""
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import server
from backend_key import AUTH, TEST_BACKEND_KEY

ROOT = Path(__file__).resolve().parents[1]
BROWSER = {"User-Agent": "Mozilla/5.0 (X11) Firefox/140.0", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"}
VEILUX = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
OTHER_EXTENSION = "chrome-extension://zyxwvutsrqponmlkzyxwvutsrqponmlk"
client = TestClient(server.app, base_url="http://localhost:8000", client=("127.0.0.1", 50000))
# Another computer on the network (documentation address range).
remote = TestClient(server.app, base_url="http://soc-box.internal:8000", client=("192.0.2.50", 50000))


def test_the_paired_extension_is_answered_in_every_browser():
    for origin in (VEILUX, "moz-extension://3f2a9c1e-7d1b-4c55-9b1e-1d2c3b4a5f6e",
                   "safari-web-extension://3F2A9C1E-7D1B-4C55-9B1E-1D2C3B4A5F6E"):
        response = client.post("/defang", json={"text": "1.2.3.4"}, headers={**BROWSER, "Origin": origin, **AUTH})
        assert response.status_code == 200, origin
        assert response.headers["access-control-allow-origin"] == origin
        # The preflight before a request with the key header carries no key itself.
        preflight = client.options("/analyze", headers={**BROWSER, "Origin": origin, "Access-Control-Request-Method": "POST",
                                                        "Access-Control-Request-Headers": "content-type,x-veilux-token"})
        assert preflight.status_code == 200, origin
        assert "x-veilux-token" in preflight.headers["access-control-allow-headers"].lower()


def test_other_extensions_are_refused_without_the_key(monkeypatch):
    called = []
    monkeypatch.setattr(server, "approved_lessons", lambda: called.append(1) or [])
    for headers in ({**BROWSER, "Origin": OTHER_EXTENSION},
                    {**BROWSER, "Origin": OTHER_EXTENSION, "X-Veilux-Token": "guessed-value-0123456789"},
                    {**BROWSER, "Origin": OTHER_EXTENSION, "X-Veilux-Token": TEST_BACKEND_KEY[:-1]},
                    {**BROWSER, "Origin": OTHER_EXTENSION, "X-Veilux-Token": TEST_BACKEND_KEY + "x"},
                    {**BROWSER, "Origin": OTHER_EXTENSION, "X-Veilux-Token": ""},
                    {"User-Agent": "Mozilla/5.0", "Sec-Fetch-Site": "none"}):  # an extension GET carries no Origin
        for method, path in (("get", "/lessons"), ("post", "/fetch-siem-logs"), ("post", "/test-siem"),
                             ("post", "/analyze"), ("post", "/threat-intel/lookup"), ("get", "/auth/check")):
            response = getattr(client, method)(path, headers=headers, **({"json": {}} if method == "post" else {}))
            assert response.status_code == 401, (headers, path)
            assert response.json()["code"] == "pairing_required"
            # The refusal is readable by the extension that asked, and only by it.
            assert response.headers.get("access-control-allow-origin") == headers.get("Origin")
    assert called == []


def test_programs_on_this_computer_need_the_key_too():
    assert client.get("/lessons", headers={"User-Agent": "curl/8.5"}).status_code == 401
    assert client.get("/lessons", headers={"User-Agent": "curl/8.5", **AUTH}).status_code == 200
    for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        local = TestClient(server.app, base_url="http://localhost:8000", client=(address, 50000))
        assert local.get("/auth/check", headers={"User-Agent": "curl/8.5"}).status_code == 401, address
        assert local.get("/auth/check", headers={"User-Agent": "curl/8.5", **AUTH}).json() == {"paired": True}, address


def test_health_answers_without_the_key_and_reveals_nothing_else():
    response = client.get("/health", headers=BROWSER)
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "version": server.VERSION}
    assert TEST_BACKEND_KEY not in response.text


def test_web_pages_are_refused_before_the_endpoint_runs_even_with_the_key(monkeypatch):
    called = []
    monkeypatch.setattr(server, "approved_lessons", lambda: called.append(1) or [])
    for origin in ("https://evil.example", "http://localhost:3000", "null", "chrome-extension://bad/../x"):
        for method, path in (("get", "/lessons"), ("post", "/test-siem"), ("post", "/pair"), ("get", "/health")):
            response = getattr(client, method)(path, headers={**BROWSER, "Origin": origin, **AUTH},
                                               **({"json": {"code": "x"}} if method == "post" else {}))
            assert response.status_code == 403, (origin, path)
            assert "access-control-allow-origin" not in response.headers
        preflight = client.options("/analyze", headers={**BROWSER, "Origin": origin, "Access-Control-Request-Method": "POST"})
        assert preflight.status_code == 403
    assert called == []


def test_dns_rebinding_is_refused():
    # A page whose own domain now points at 127.0.0.1: same-site, so no Origin.
    response = client.get("/lessons", headers={"Host": "attacker.example:8000", "User-Agent": "Mozilla/5.0",
                                                "Sec-Fetch-Site": "same-origin", **AUTH})
    assert response.status_code == 403
    for host in ("localhost:8000", "127.0.0.1:8000", "[::1]:8000"):
        assert client.get("/health", headers={"Host": host, "User-Agent": "Mozilla/5.0"}).status_code == 200


def test_named_hosts_and_other_computers_with_the_key(monkeypatch):
    monkeypatch.setattr(server, "ALLOWED_HOSTS", {"soc-box.internal"})
    assert remote.get("/lessons", headers={**BROWSER, "Origin": VEILUX}).status_code == 401
    assert remote.get("/lessons", headers={**BROWSER, "Origin": VEILUX, **AUTH}).status_code == 200
    assert remote.get("/lessons", headers={"User-Agent": "curl/8.5", **AUTH}).status_code == 200


def open_pairing(monkeypatch):
    monkeypatch.setattr(server, "PAIRING", {"code": "", "expires": 0.0, "failures": 0})
    return server.new_pairing_code()


def test_pairing_code_gives_the_key_to_the_extension(monkeypatch):
    code = open_pairing(monkeypatch)
    assert len(code) == 9 and code[4] == "-" and set(code.replace("-", "")) <= set(server.PAIRING_CODE_ALPHABET)
    headers = {**BROWSER, "Origin": VEILUX}
    for spelling in (code, code.lower(), code.replace("-", " "), code.replace("-", "")):
        response = client.post("/pair", json={"code": spelling}, headers=headers)
        assert response.status_code == 200, spelling
        assert response.json() == {"token": TEST_BACKEND_KEY}
    # The key it returns then opens every endpoint.
    assert client.get("/auth/check", headers={**headers, "X-Veilux-Token": response.json()["token"]}).status_code == 200


def test_wrong_pairing_codes_disable_the_code_after_five_tries(monkeypatch):
    code = open_pairing(monkeypatch)
    for left in (4, 3, 2, 1):
        response = client.post("/pair", json={"code": "AAAA-AAAA"}, headers={**BROWSER, "Origin": OTHER_EXTENSION})
        assert response.status_code == 401 and f"{left} tries left" in response.json()["detail"]
        assert "token" not in response.json()
    response = client.post("/pair", json={"code": "AAAA-AAAA"}, headers=BROWSER)
    assert response.status_code == 401 and "disabled" in response.json()["detail"]
    # Even the right code no longer works: a new one needs a restart.
    response = client.post("/pair", json={"code": code}, headers=BROWSER)
    assert response.status_code == 410 and TEST_BACKEND_KEY not in response.text


def test_pairing_code_expires_and_is_only_for_this_computer(monkeypatch):
    code = open_pairing(monkeypatch)
    for forwarded in ({"X-Forwarded-For": "198.51.100.7"}, {"Forwarded": "for=198.51.100.7"}):
        response = client.post("/pair", json={"code": code}, headers={**BROWSER, **forwarded})
        assert response.status_code == 403 and TEST_BACKEND_KEY not in response.text
    monkeypatch.setattr(server, "ALLOWED_HOSTS", {"soc-box.internal"})
    assert remote.post("/pair", json={"code": code}, headers=BROWSER).status_code == 403
    server.PAIRING["expires"] = time.monotonic() - 1
    assert client.post("/pair", json={"code": code}, headers=BROWSER).status_code == 410
    monkeypatch.setattr(server, "PAIRING", {"code": "", "expires": 0.0, "failures": 0})
    assert client.post("/pair", json={"code": ""}, headers=BROWSER).status_code == 410
    assert client.post("/pair", json={"code": "x" * 65}, headers=BROWSER).status_code == 422


def test_without_a_key_everything_but_health_and_pairing_is_refused(monkeypatch):
    monkeypatch.setattr(server, "ACCESS_TOKEN", "")
    assert client.get("/lessons", headers={**BROWSER, "Origin": VEILUX, "X-Veilux-Token": ""}).status_code == 401
    assert client.get("/lessons", headers={"User-Agent": "curl/8.5", **AUTH}).status_code == 401
    assert client.get("/health").status_code == 200


def test_key_file_is_private_strong_and_reused(tmp_path):
    path = tmp_path / "veilux_backend.key"
    key = server.load_or_create_key(str(path))
    assert len(key) >= 40 and path.read_text().strip() == key
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert server.load_or_create_key(str(path)) == key
    path.write_text("short\n")
    try:
        server.load_or_create_key(str(path))
        raise AssertionError("a short key file must be refused")
    except ValueError as error:
        assert "Delete it" in str(error)


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


@posix_only
def test_a_readable_key_file_is_made_private_and_kept(tmp_path, caplog):
    # A key created by an older build, or copied with loose permissions.
    path = tmp_path / "veilux_backend.key"
    path.write_text(TEST_BACKEND_KEY + "\n")
    for loose in (0o644, 0o640, 0o604, 0o666, 0o700):
        os.chmod(path, loose)
        assert server.load_or_create_key(str(path)) == TEST_BACKEND_KEY
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, oct(loose)
    assert "now private" in caplog.text
    caplog.clear()
    server.load_or_create_key(str(path))
    assert "now private" not in caplog.text


@posix_only
def test_a_key_file_of_another_user_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "veilux_backend.key"
    path.write_text(TEST_BACKEND_KEY + "\n")
    os.chmod(path, 0o600)
    monkeypatch.setattr(server.os, "geteuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(server.KeyFileError, match="another user"):
        server.load_or_create_key(str(path))


@posix_only
def test_a_link_in_place_of_the_key_file_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere"
    path = tmp_path / "veilux_backend.key"
    path.symlink_to(target)
    with pytest.raises(FileExistsError):
        server.load_or_create_key(str(path))
    assert not target.exists()


def test_no_key_is_written_when_permissions_cannot_be_set(tmp_path, monkeypatch):
    path = tmp_path / "veilux_backend.key"

    def refuse(_path):
        raise server.KeyFileError("not allowed")
    monkeypatch.setattr(server, "restrict_key_file", refuse)
    with pytest.raises(server.KeyFileError):
        server.load_or_create_key(str(path))
    assert not path.exists()


def test_windows_key_file_is_limited_to_this_account(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **_options):
        calls.append(command)
        out = '"desktop\\analyst","S-1-5-21-1004336348-1177238915-682003330-1001"\r\n' if "whoami" in command[0] else ""
        return subprocess.CompletedProcess(command, 0, stdout=out, stderr="")
    monkeypatch.setattr(server.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    server.restrict_key_file("C:\\veilux\\veilux_backend.key")
    whoami, icacls = calls
    # Full paths: a program of the same name in the current folder is never run.
    assert whoami[0].endswith("System32" + os.sep + "whoami.exe") and whoami[0].startswith("C:")
    assert icacls[0].endswith("System32" + os.sep + "icacls.exe")
    assert icacls[1:] == ["C:\\veilux\\veilux_backend.key", "/inheritance:r", "/grant:r",
                          "*S-1-5-21-1004336348-1177238915-682003330-1001:F"]

    def failing_run(command, **_options):
        raise subprocess.CalledProcessError(5, command)
    monkeypatch.setattr(server.subprocess, "run", failing_run)
    with pytest.raises(server.KeyFileError, match="your account"):
        server.restrict_key_file("C:\\veilux\\veilux_backend.key")


@posix_only
def test_macos_key_file_drops_inherited_access_lists(tmp_path, monkeypatch):
    path = tmp_path / "veilux_backend.key"
    calls = []
    monkeypatch.setattr(server.sys, "platform", "darwin")
    monkeypatch.setattr(server.subprocess, "run",
                        lambda command, **_o: calls.append(command) or subprocess.CompletedProcess(command, 0))
    key = server.load_or_create_key(str(path))
    assert calls == [["/bin/chmod", "-N", str(path)]]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.read_text().strip() == key


@pytest.mark.skipif(os.name != "nt", reason="needs Windows")
def test_windows_key_file_has_no_inherited_access(tmp_path):
    path = tmp_path / "veilux_backend.key"
    server.load_or_create_key(str(path))
    listing = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    entries = listing.replace(str(path), "")
    assert "(I)" not in entries, listing
    assert "BUILTIN\\Users" not in entries and "Everyone" not in entries, listing


def test_loopback_detection():
    for host in ("127.0.0.1", "127.0.0.2", "::1", "[::1]", "localhost", "::ffff:127.0.0.1"):
        assert server.is_loopback_address(host), host
    for host in ("0.0.0.0", "::", "192.0.2.1", "10.0.0.5", "soc-box.internal", "", "::ffff:192.0.2.1", "127.0.0.1.example"):
        assert not server.is_loopback_address(host), host


def _start(tmp_path, *args, token=None, binary=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VEILUX_")}
    env["VEILUX_KEY_FILE"] = str(tmp_path / "veilux_backend.key")
    if token is not None:
        env["VEILUX_TOKEN"] = token
    # The backend writes UTF-8 (it reconfigures its output at start-up, for the
    # emoji in its messages). Decode it as UTF-8: text=True alone would use the
    # locale code page, cp1252 on most Windows computers, which cannot decode
    # every byte the emoji use; communicate() then silently returns None.
    text = {} if binary else {"encoding": "utf-8"}
    return subprocess.Popen([sys.executable, "server.py", *args], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **text)


class _Output:
    """Reads one of a running backend's pipes line by line, as it is written."""
    def __init__(self, pipe):
        self.lines, self.undecodable = [], []
        self.thread = threading.Thread(target=self._read, args=(pipe,), daemon=True)
        self.thread.start()

    def _read(self, pipe):
        for raw in iter(pipe.readline, b""):
            try:
                self.lines.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self.undecodable.append(repr(raw))
                self.lines.append(raw.decode("utf-8", "replace"))

    @property
    def text(self):
        return "".join(self.lines)


def test_backend_refuses_a_short_veilux_token(tmp_path):
    for host in ("127.0.0.1", "0.0.0.0"):
        process = _start(tmp_path, "--host", host, "--port", "8797", token="too-short")
        _, err = process.communicate(timeout=60)
        assert process.returncode == 2, host
        assert "VEILUX_TOKEN" in err and "Not starting" in err
    assert not (tmp_path / "veilux_backend.key").exists()


def test_backend_creates_its_key_and_shows_a_pairing_code(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = _start(tmp_path, "--port", str(port), binary=True)
    out, err = _Output(process.stdout), _Output(process.stderr)
    base = f"http://127.0.0.1:{port}"
    try:
        # The code is shown while the backend starts (written at once, not
        # held in a buffer until it stops), and it is a working pairing code.
        deadline = time.monotonic() + 60
        while "Pairing code:" not in out.text:
            assert process.poll() is None, f"backend exited with {process.returncode}:\n{out.text}{err.text}"
            assert time.monotonic() < deadline, f"no pairing code after 60 s:\n{out.text}{err.text}"
            time.sleep(0.1)
        code = re.search(r"Pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4})", out.text).group(1)
        for _ in range(100):
            try:
                assert httpx.get(base + "/health", timeout=1, trust_env=False).json()["status"] == "healthy"
                break
            except httpx.TransportError:
                assert process.poll() is None, f"{out.text}{err.text}"
                time.sleep(0.2)
        else:
            raise AssertionError("backend did not start")
        key = (tmp_path / "veilux_backend.key").read_text().strip()
        assert httpx.get(base + "/lessons", timeout=2, trust_env=False).status_code == 401
        assert httpx.get(base + "/lessons", headers={"X-Veilux-Token": key}, timeout=2, trust_env=False).status_code == 200
        paired = httpx.post(base + "/pair", json={"code": code}, timeout=2, trust_env=False)
        assert paired.status_code == 200 and paired.json()["token"] == key
    finally:
        process.terminate()
        process.wait(timeout=10)
        out.thread.join(10)
        err.thread.join(10)
    # Neither output ever shows the key itself; both are valid UTF-8; the key
    # file's location (not its content) is shown.
    assert key not in out.text and key not in err.text
    assert out.undecodable == [] and err.undecodable == []
    assert "Backend key: " + str(tmp_path / "veilux_backend.key") in out.text
