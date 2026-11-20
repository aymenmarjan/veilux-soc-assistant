"""Release packaging: icons, extension archives and the platform launchers.

The standalone backends themselves are built and checked by the Release
packages workflow on each system (packaging/build_backend.py,
check_package.py and smoke_test.py); these tests cover what can be checked
anywhere, without PyInstaller.
"""
import os
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / "packaging" / "icons"
sys.path.insert(0, str(ROOT / "packaging"))
import build_backend  # noqa: E402


def png_size(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II", data[16:24])


def test_windows_icon_has_every_size_as_png():
    data = (ICONS / "veilux.ico").read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind, count) == (0, 1, 7)
    sizes = []
    for i in range(count):
        width, height, _, _, _, _, length, offset = struct.unpack("<BBBBHHII", data[6 + 16 * i:22 + 16 * i])
        assert png_size(data[offset:offset + length]) == (width or 256, height or 256)
        sizes.append(width or 256)
    assert sizes == [16, 24, 32, 48, 64, 128, 256]


def test_macos_icon_has_standard_and_retina_sizes():
    data = (ICONS / "veilux.icns").read_bytes()
    assert data[:4] == b"icns" and struct.unpack(">I", data[4:8])[0] == len(data)
    entries, at = {}, 8
    while at < len(data):
        kind, length = data[at:at + 4].decode(), struct.unpack(">I", data[at + 4:at + 8])[0]
        entries[kind] = png_size(data[at + 8:at + length])
        at += length
    assert entries == {"icp4": (16, 16), "icp5": (32, 32), "icp6": (64, 64), "ic07": (128, 128), "ic08": (256, 256),
                       "ic09": (512, 512), "ic10": (1024, 1024), "ic11": (32, 32), "ic12": (64, 64),
                       "ic13": (256, 256), "ic14": (512, 512)}


def test_linux_icons_and_the_icon_source():
    for size in (16, 24, 32, 48, 64, 128, 256, 512):
        assert png_size((ICONS / "linux" / f"{size}x{size}.png").read_bytes()) == (size, size)
    assert png_size((ICONS / "veilux-mascot.png").read_bytes()) == (1312, 1199)


def test_icons_are_regenerated_identically(tmp_path):
    """The committed icons are what make_icons.py produces from the mascot."""
    pytest.importorskip("PIL")
    copy = tmp_path / "packaging"
    (copy / "icons").mkdir(parents=True)
    (copy / "icons" / "veilux-mascot.png").write_bytes((ICONS / "veilux-mascot.png").read_bytes())
    (copy / "make_icons.py").write_bytes((ROOT / "packaging" / "make_icons.py").read_bytes())
    subprocess.run([sys.executable, str(copy / "make_icons.py")], check=True, capture_output=True, timeout=300)
    for name in ("veilux.ico", "veilux.icns", "linux/16x16.png", "linux/512x512.png"):
        assert (copy / "icons" / name).read_bytes() == (ICONS / name).read_bytes(), name


def test_extension_packages_are_exactly_the_extension(tmp_path):
    subprocess.run([sys.executable, "packaging/build_extensions.py", str(tmp_path)], cwd=ROOT, check=True, capture_output=True)
    result = subprocess.run([sys.executable, "packaging/check_package.py", str(tmp_path / "veilux-1.0.0-chromium.zip"),
                             str(tmp_path / "veilux-1.0.0-firefox.xpi")], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_macos_app_opens_the_backend_in_terminal(tmp_path):
    folder = tmp_path / "VEILUX folder"
    folder.mkdir()
    (folder / "veilux-backend").write_text("#!/bin/sh\n")
    (folder / "veilux-backend").chmod(0o755)
    build_backend.macos_launcher(folder, "1.0.0")
    contents = folder / "VEILUX Backend.app" / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    assert info["CFBundleIconFile"] == "veilux" and info["CFBundleExecutable"] == "veilux-launcher"
    assert (contents / "Resources" / "veilux.icns").read_bytes() == (ICONS / "veilux.icns").read_bytes()
    if os.name == "nt":
        pytest.skip("runs the launcher with bash")
    out = subprocess.run([str(contents / "MacOS" / "veilux-launcher")], capture_output=True, text=True,
                         env={**os.environ, "VEILUX_OPEN": "echo"}, timeout=30).stdout.split()
    assert out[:2] == ["-a", "Terminal"] and Path(" ".join(out[2:])).resolve() == (folder / "veilux-backend").resolve()


@pytest.mark.skipif(os.name == "nt", reason="Linux desktop entry")
def test_linux_menu_entry_points_at_the_backend(tmp_path):
    folder = tmp_path / "veilux backend"
    folder.mkdir()
    build_backend.linux_icons(folder)
    data = tmp_path / "data"
    subprocess.run([str(folder / "install-desktop-entry.sh")], check=True, capture_output=True,
                   env={**os.environ, "XDG_DATA_HOME": str(data)}, timeout=30)
    entry = (data / "applications" / "veilux-backend.desktop").read_text()
    assert f'Exec="{folder.resolve()}/veilux-backend"' in entry and "Terminal=true" in entry and "Icon=veilux-backend" in entry
    assert png_size((data / "icons/hicolor/256x256/apps/veilux-backend.png").read_bytes()) == (256, 256)


def test_windows_version_details(tmp_path):
    build_backend.windows_version_file(tmp_path / "v.txt", "1.0.0")
    text = (tmp_path / "v.txt").read_text()
    assert "filevers=(1, 0, 0, 0)" in text and "StringStruct('ProductName', 'VEILUX')" in text
    assert "StringStruct('OriginalFilename', 'veilux-backend.exe')" in text
