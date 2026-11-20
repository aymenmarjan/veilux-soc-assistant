"""Checks that a release package holds what it should, and nothing private.

    python packaging/check_package.py dist/veilux-backend-1.0.0-linux-x64.tar.gz
    python packaging/check_package.py dist/veilux-1.0.0-chromium.zip

Backend packages: the program, its libraries, start instructions, licences
and build record; the platform's icon assets (Windows: the icon and version
details inside the .exe; macOS: the app bundle that opens Terminal; Linux:
hicolor icons and the menu-entry installer, which is run into a temporary
folder). Extension packages: exactly the files of extension/. Every package:
no key file, lessons, cache, settings or secrets.
"""
import json
import os
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = {"veilux_backend.key", "training_feedback.json", "threat_intel_cache.json", "config.json", ".env"}
LINUX_SIZES = [16, 24, 32, 48, 64, 128, 256, 512]


def check(label, condition, detail=""):
    if not condition:
        raise AssertionError(f"{label} {detail}".strip())
    print(f"  PASS  {label}")


def png_size(path):
    data = path.read_bytes()[:24]
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", data[16:24])


def check_extension(folder):
    files = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())
    expected = sorted(p.relative_to(ROOT / "extension").as_posix() for p in (ROOT / "extension").rglob("*")
                      if p.is_file() and "__pycache__" not in p.parts)
    check("the package holds exactly the files of extension/", files == expected,
          f"extra {set(files) - set(expected)}, missing {set(expected) - set(files)}")
    same = all((folder / f).read_bytes() == (ROOT / "extension" / f).read_bytes() for f in files)
    check("every file is byte-for-byte as committed", same)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    check("manifest version 1.0.0 and its icons", manifest["version"] == "1.0.0"
          and all((folder / icon).is_file() for icon in manifest["icons"].values()))


def check_windows(top):
    program = top / "veilux-backend.exe"
    check("veilux-backend.exe", program.is_file())
    try:
        import pefile
    except ImportError:
        print("  SKIP  icon and version details (pefile is not installed)")
        return
    pe = pefile.PE(str(program))
    groups = [e for e in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries
              if e.id == pefile.RESOURCE_TYPE["RT_GROUP_ICON"]] if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else []
    icons = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE["RT_ICON"]]
    count = len(icons[0].directory.entries) if icons else 0
    check("the .exe carries the VEILUX icon (7 sizes)", bool(groups) and count == 7, f"{count} icon images")
    strings = {}
    for info in getattr(pe, "FileInfo", []) or []:
        for entry in info:
            for table in getattr(entry, "StringTable", []):
                strings.update({k.decode(): v.decode() for k, v in table.entries.items()})
    pe.close()   # pefile keeps the file open; Windows cannot delete it otherwise
    check("the .exe carries its version details", strings.get("ProductName") == "VEILUX"
          and strings.get("ProductVersion") == "1.0.0" and strings.get("FileDescription") == "VEILUX backend", str(strings))


def check_macos(top):
    program = top / "veilux-backend"
    check("veilux-backend", program.is_file() and os.access(program, os.X_OK))
    app = top / "VEILUX Backend.app" / "Contents"
    info = plistlib.loads((app / "Info.plist").read_bytes())
    check("VEILUX Backend.app has a valid Info.plist", info["CFBundleExecutable"] == "veilux-launcher"
          and info["CFBundleIconFile"] == "veilux" and info["CFBundleShortVersionString"] == "1.0.0")
    icns = (app / "Resources" / "veilux.icns").read_bytes()
    check("the app carries the VEILUX icon", icns[:4] == b"icns" and b"ic10" in icns and b"icp4" in icns)
    launcher = app / "MacOS" / "veilux-launcher"
    check("the app's launcher is executable", os.access(launcher, os.X_OK))
    result = subprocess.run([str(launcher)], capture_output=True, text=True, timeout=30,
                            env={**os.environ, "VEILUX_OPEN": "echo"})
    words = result.stdout.split()
    # /var on macOS is a link to /private/var: compare the resolved paths.
    opened = Path(" ".join(words[2:])).resolve() if len(words) > 2 else None
    check("the app opens the backend next to it in Terminal",
          result.returncode == 0 and words[:2] == ["-a", "Terminal"] and opened == program.resolve(), result.stdout + result.stderr)


def check_linux(top):
    program = top / "veilux-backend"
    check("veilux-backend", program.is_file() and os.access(program, os.X_OK))
    for size in LINUX_SIZES:
        icon = top / "icons" / "hicolor" / f"{size}x{size}" / "apps" / "veilux-backend.png"
        assert icon.is_file() and png_size(icon) == (size, size), icon
    check(f"hicolor icons in {len(LINUX_SIZES)} sizes", True)
    installer = top / "install-desktop-entry.sh"
    check("install-desktop-entry.sh is executable", os.access(installer, os.X_OK))
    with tempfile.TemporaryDirectory() as data:
        result = subprocess.run([str(installer)], capture_output=True, text=True, timeout=30,
                                env={**os.environ, "XDG_DATA_HOME": data})
        entry = Path(data, "applications", "veilux-backend.desktop")
        text = entry.read_text() if entry.exists() else ""
        check("the menu entry opens the backend in a terminal, with the icon",
              result.returncode == 0 and f'Exec="{program.resolve()}"' in text and "Icon=veilux-backend" in text
              and "Terminal=true" in text and Path(data, "icons/hicolor/48x48/apps/veilux-backend.png").is_file(),
              result.stdout + result.stderr + text)
        if shutil.which("desktop-file-validate"):
            valid = subprocess.run(["desktop-file-validate", str(entry)], capture_output=True, text=True)
            check("desktop-file-validate accepts the entry", valid.returncode == 0, valid.stdout + valid.stderr)


def main(archive):
    archive = Path(archive)
    with tempfile.TemporaryDirectory(prefix="veilux-check-") as tmp:
        shutil.unpack_archive(str(archive), tmp, "zip" if archive.suffix in (".zip", ".xpi") else None)
        root = Path(tmp)
        names = {p.name for p in root.rglob("*")}
        check("no key file, lessons, cache, settings or secrets", not (names & PRIVATE), str(names & PRIVATE))
        if archive.name.startswith("veilux-backend-"):
            (top,) = [p for p in root.iterdir() if p.is_dir()]
            for name in ("HOW-TO-START.txt", "LICENSE", "NOTICE", "BUILD-INFO.txt", "THIRD_PARTY_LICENSES/README.txt", "_internal"):
                assert (top / name).exists(), name
            check("start instructions, licences and build record", True)
            system = archive.name.split("-")[3]
            {"windows": check_windows, "macos": check_macos, "linux": check_linux}[system](top)
        else:
            check_extension(root)
    print(f"{archive.name}: all package checks passed.")


if __name__ == "__main__":
    for path in sys.argv[1:] or sys.exit(__doc__):
        main(path)
