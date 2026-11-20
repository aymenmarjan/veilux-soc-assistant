"""Where the backend keeps its data, how it writes it, and how it starts and stops."""
import json
import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import server

ROOT = Path(__file__).resolve().parents[1]
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


def test_data_folder_per_system(monkeypatch, tmp_path):
    monkeypatch.delenv("VEILUX_DATA_DIR", raising=False)
    # Run from source: the folder the backend is started from, as before.
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert server.default_data_dir() == ""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(sys, "platform", "linux")
    assert server.default_data_dir() == str(tmp_path / "xdg" / "veilux")
    monkeypatch.delenv("XDG_DATA_HOME")
    assert server.default_data_dir() == os.path.join(str(tmp_path), ".local", "share", "veilux")
    monkeypatch.setattr(sys, "platform", "darwin")
    assert server.default_data_dir() == os.path.join(str(tmp_path), "Library", "Application Support", "VEILUX")
    monkeypatch.setenv("VEILUX_DATA_DIR", str(tmp_path / "chosen"))
    assert server.default_data_dir() == str(tmp_path / "chosen")


def test_windows_data_folder_is_local_app_data(monkeypatch):
    monkeypatch.delenv("VEILUX_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(server.os, "name", "nt")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\analyst\AppData\Local")
    assert server.default_data_dir() == os.path.join(r"C:\Users\analyst\AppData\Local", "VEILUX")


@posix_only
def test_a_new_data_folder_is_private_and_an_existing_one_is_left_alone(tmp_path):
    new = tmp_path / "VEILUX"
    server.prepare_data_dir(str(new))
    assert stat.S_IMODE(new.stat().st_mode) == 0o700
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)
    server.prepare_data_dir(str(shared))
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755


def test_json_files_are_replaced_whole(tmp_path):
    target = tmp_path / "lessons.json"
    server.write_json_atomically(str(target), {"feedback_entries": [{"id": "a"}]})
    assert json.loads(target.read_text()) == {"feedback_entries": [{"id": "a"}]}
    # A write that fails half-way leaves the previous file intact and no temporary file.
    with pytest.raises(TypeError):
        server.write_json_atomically(str(target), {"feedback_entries": [object()]})
    assert json.loads(target.read_text()) == {"feedback_entries": [{"id": "a"}]}
    assert [p.name for p in tmp_path.iterdir()] == ["lessons.json"]
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_an_unreadable_data_file_is_kept_aside_not_fatal(tmp_path, caplog):
    target = tmp_path / "threat_intel_cache.json"
    assert server.load_json_file(str(target), {}, "The cache") == {}
    target.write_text('{"half": ')
    assert server.load_json_file(str(target), {}, "The cache") == {}
    assert (tmp_path / "threat_intel_cache.json.unreadable").read_text() == '{"half": '
    assert "could not be read" in caplog.text and not target.exists()
    target.write_text("[1, 2]")
    assert server.load_json_file(str(target), {}, "The cache") == {}
    target.write_text('{"ok": 1}')
    assert server.load_json_file(str(target), {}, "The cache") == {"ok": 1}


def test_port_check(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert not server.port_available("127.0.0.1", port)
    assert server.port_available("127.0.0.1", port)


def test_start_pair_use_stop_restart():
    """The same checks the release workflow runs against each packaged backend."""
    result = subprocess.run([sys.executable, "packaging/smoke_test.py", sys.executable, "server.py"],
                            cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All smoke checks passed." in result.stdout
