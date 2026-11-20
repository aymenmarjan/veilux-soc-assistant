"""Builds the standalone VEILUX backend for the system it runs on.

    pip install -r requirements.txt pyinstaller==6.22.3
    python packaging/build_backend.py [output folder, default dist]

PyInstaller bundles Python, the backend and its dependencies into one folder,
so users need no Python installation. It cannot cross-compile: build on each
target system (the release workflow uses a runner per system).

Writes veilux-backend-<version>-<system>.zip (Windows) or .tar.gz (Linux,
macOS) containing:
  veilux-backend[.exe]   the program; run it and keep its window open
                         (Windows: with the VEILUX icon and version details)
  _internal/             Python and the libraries it needs
  VEILUX Backend.app     macOS: opens the program in Terminal, with the icon
  icons/, install-desktop-entry.sh
                         Linux: icons and an optional application-menu entry
  HOW-TO-START.txt       first start, pairing, stopping, where data is kept
  LICENSE, NOTICE        VEILUX's licence
  THIRD_PARTY_LICENSES/  the licences of Python and every bundled library
  BUILD-INFO.txt         commit, build date and exact library versions
"""
import importlib.metadata as metadata
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ICONS = ROOT / "packaging" / "icons"   # made by packaging/make_icons.py
NAME = "veilux-backend"
# Build tools: present in the build environment, not shipped.
BUILD_ONLY = {"pyinstaller", "pyinstaller-hooks-contrib", "altgraph", "macholib", "pefile", "pywin32-ctypes",
              "pip", "setuptools", "wheel", "packaging"}


def system_tag():
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
    return f"{system}-{arch}"


def version():
    return re.search(r'^VERSION = "([^"]+)"', (ROOT / "server.py").read_text(encoding="utf-8"), re.M).group(1)


def runtime_distributions():
    """The installed distributions server.py needs, following their requirements."""
    wanted = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            wanted.append(re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0])
    seen = {}
    while wanted:
        name = wanted.pop().lower().replace("_", "-")
        if name in seen or name in BUILD_ONLY:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen[name] = dist
        for requirement in dist.requires or []:
            if "extra ==" in requirement:
                continue
            marker = requirement.split(";", 1)
            if len(marker) == 2 and not _marker_applies(marker[1]):
                continue
            wanted.append(re.split(r"[<>=!~;\[ (]", requirement.strip(), maxsplit=1)[0])
    return dict(sorted(seen.items()))


def _marker_applies(marker):
    try:
        from packaging.markers import Marker
        return Marker(marker).evaluate()
    except Exception:
        return True


def copy_licences(dists, target: Path):
    target.mkdir()
    python_licence = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_licence.exists():
        python_licence = next(Path(sys.base_prefix).glob("lib/python3*/LICENSE.txt"), None) or Path(sys.base_prefix) / "LICENSE"
    lines = [f"Python {platform.python_version()}: Python Software Foundation License"]
    if python_licence and python_licence.exists():
        shutil.copy(python_licence, target / "Python-LICENSE.txt")
    for name, dist in dists.items():
        files = [f for f in (dist.files or []) if re.search(r"(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", f.name, re.I)
                 and "dist-info" in str(f) or "/licenses/" in str(f).replace("\\", "/")]
        copied = []
        for file in files:
            source = Path(dist.locate_file(file))
            if source.is_file():
                destination = target / f"{dist.metadata['Name']}-{source.name}"
                shutil.copy(source, destination)
                copied.append(destination.name)
        licence = dist.metadata.get("License-Expression") or dist.metadata.get("License") or ""
        classifiers = [c.split("::")[-1].strip() for c in dist.metadata.get_all("Classifier") or [] if c.startswith("License ::")]
        summary = licence.splitlines()[0][:80] if licence and len(licence) < 200 else ", ".join(classifiers)
        lines.append(f"{dist.metadata['Name']} {dist.version}: {summary or 'see files'}"
                     + ("" if copied else "  (no licence file in the package metadata)"))
    (target / "README.txt").write_text(
        "Licences of the software bundled in this program, besides VEILUX itself (see LICENSE and NOTICE).\n"
        "The program is built with PyInstaller, whose bootloader is distributed under the GPL with an\n"
        "exception that allows bundling it with programs under any licence.\n\n" + "\n".join(lines) + "\n",
        encoding="utf-8")


HOW_TO_START = {
    "windows": """\
VEILUX backend {version} for Windows (x64)

START
  1. Extract this folder anywhere you can write to, for example your Documents.
  2. Double-click veilux-backend.exe. A console window opens; keep it open while
     you use VEILUX.
     Windows may warn that the publisher is unknown, because this build is not
     code-signed: choose "More info", then "Run anyway", only if you downloaded
     it from the official VEILUX release and its SHA-256 checksum matches.
  3. The window shows a pairing code, such as "Pairing code: ABCD-2345".
     In the browser: VEILUX settings -> Backend -> enter the code -> Pair.
     Needed once per browser. The code is valid for 15 minutes; restart the
     backend for a new one.

STOP
  Press Ctrl+C in the window (or close it). Data is written safely either way.

DATA
  %LOCALAPPDATA%\\VEILUX holds the backend key (readable only by your account),
  your lessons and the threat-intelligence cache. To use another folder, set
  the VEILUX_DATA_DIR environment variable. Deleting the key file makes a new
  key: every browser then pairs again.

OPTIONS
  veilux-backend.exe --port 8100     another port (then set the backend address
                                     in VEILUX settings -> Backend)
  veilux-backend.exe --version
""",
    "macos": """\
VEILUX backend {version} for macOS ({arch})

START
  1. Extract this archive (double-click it), for example in your Documents.
  2. The first time: open Terminal in the extracted folder and run
         xattr -dr com.apple.quarantine .
     This build is not signed by an Apple developer ID, so macOS would block it.
     Do this only if you downloaded it from the official VEILUX release and its
     SHA-256 checksum matches.
  3. Start it: double-click "VEILUX Backend" (it opens the backend in
     Terminal), or run
         ./veilux-backend
     Keep the Terminal window open while you use VEILUX. You can drag
     "VEILUX Backend" to the Dock; keep it in this folder, next to
     veilux-backend.
  4. The window shows a pairing code, such as "Pairing code: ABCD-2345".
     In the browser: VEILUX settings -> Backend -> enter the code -> Pair.
     Needed once per browser. The code is valid for 15 minutes; restart the
     backend for a new one.

STOP
  Press Ctrl+C in the window. Data is written safely even if it is closed.

DATA
  ~/Library/Application Support/VEILUX holds the backend key (readable only by
  you), your lessons and the threat-intelligence cache. To use another folder,
  set VEILUX_DATA_DIR. Deleting the key file makes a new key: every browser
  then pairs again.

OPTIONS
  ./veilux-backend --port 8100       another port (then set the backend address
                                     in VEILUX settings -> Backend)
  ./veilux-backend --version
""",
    "linux": """\
VEILUX backend {version} for Linux (x64)

Needs glibc 2.35 or later (Ubuntu 22.04, Debian 12, Fedora 36 or later). On
older systems, run the backend from source with Python 3.12 or later.

START
  1. Extract:   tar -xzf veilux-backend-{version}-linux-x64.tar.gz
  2. Run:       ./veilux-backend-{version}-linux-x64/veilux-backend
     Keep the terminal open while you use VEILUX.
  3. The terminal shows a pairing code, such as "Pairing code: ABCD-2345".
     In the browser: VEILUX settings -> Backend -> enter the code -> Pair.
     Needed once per browser. The code is valid for 15 minutes; restart the
     backend for a new one.

  4. Optional: add VEILUX to your application menu (for your user only):
         ./veilux-backend-{version}-linux-x64/install-desktop-entry.sh
     It opens the backend in a terminal. Run it again after moving the
     folder.

STOP
  Press Ctrl+C (or send SIGTERM). Data is written safely either way.

DATA
  $XDG_DATA_HOME/veilux (usually ~/.local/share/veilux, mode 0700) holds the
  backend key (mode 0600), your lessons and the threat-intelligence cache. To
  use another folder, set VEILUX_DATA_DIR. Deleting the key file makes a new
  key: every browser then pairs again.

OPTIONS
  ./veilux-backend --port 8100       another port (then set the backend address
                                     in VEILUX settings -> Backend)
  ./veilux-backend --version
""",
}


def windows_version_file(path: Path, ver: str):
    """The details Windows shows in the program's Properties."""
    numbers = tuple(int(n) for n in (ver.split(".") + ["0"] * 4)[:4])
    path.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'VEILUX'),
      StringStruct('FileDescription', 'VEILUX backend'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', '{NAME}'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 Aymen Marjan and contributors. Apache License 2.0.'),
      StringStruct('OriginalFilename', '{NAME}.exe'),
      StringStruct('ProductName', 'VEILUX'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")


MACOS_LAUNCHER = """#!/bin/bash
# Opens the VEILUX backend next to this app in a Terminal window, so its
# pairing code and messages stay visible. VEILUX_OPEN lets tests check it.
here="$(cd "$(dirname "$0")/../../.." && pwd)"
if [ ! -x "$here/veilux-backend" ]; then
  /usr/bin/osascript -e 'display alert "VEILUX Backend" message "Keep this app in the folder that contains veilux-backend."' >/dev/null 2>&1
  exit 1
fi
exec "${VEILUX_OPEN:-/usr/bin/open}" -a Terminal "$here/veilux-backend"
"""


def macos_launcher(staging: Path, ver: str):
    """A small app bundle with the VEILUX icon. The backend itself stays a
    console program: a GUI app would hide its pairing code."""
    contents = staging / "VEILUX Backend.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Resources").mkdir()
    shutil.copy(ICONS / "veilux.icns", contents / "Resources" / "veilux.icns")
    launcher = contents / "MacOS" / "veilux-launcher"
    launcher.write_text(MACOS_LAUNCHER, encoding="utf-8")
    launcher.chmod(0o755)
    (contents / "Info.plist").write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>VEILUX Backend</string>
  <key>CFBundleDisplayName</key><string>VEILUX Backend</string>
  <key>CFBundleIdentifier</key><string>io.github.aymenmarjan.veilux.backend</string>
  <key>CFBundleVersion</key><string>{ver}</string>
  <key>CFBundleShortVersionString</key><string>{ver}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>veilux-launcher</string>
  <key>CFBundleIconFile</key><string>veilux</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHumanReadableCopyright</key><string>Copyright (c) 2026 Aymen Marjan and contributors. Apache License 2.0.</string>
</dict>
</plist>
""", encoding="utf-8")


LINUX_DESKTOP_INSTALLER = """#!/bin/sh
# Adds the VEILUX backend to your application menu, for your user only.
# The menu entry opens it in a terminal, where its pairing code is shown.
# Run it again after moving this folder. To remove the entry:
#   rm "${XDG_DATA_HOME:-$HOME/.local/share}/applications/veilux-backend.desktop"
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
data="${XDG_DATA_HOME:-$HOME/.local/share}"
for icon in "$here"/icons/hicolor/*/apps/veilux-backend.png; do
  size="$(basename "$(dirname "$(dirname "$icon")")")"
  mkdir -p "$data/icons/hicolor/$size/apps"
  cp "$icon" "$data/icons/hicolor/$size/apps/veilux-backend.png"
done
mkdir -p "$data/applications"
cat > "$data/applications/veilux-backend.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=VEILUX backend
Comment=Local backend of the VEILUX SOC assistant
Exec="$here/veilux-backend"
Icon=veilux-backend
Terminal=true
Categories=Utility;Network;
ENTRY
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$data/applications" >/dev/null 2>&1 || true
echo "Added VEILUX backend to the application menu."
"""


def linux_icons(staging: Path):
    for png in sorted((ICONS / "linux").glob("*.png")):
        target = staging / "icons" / "hicolor" / png.stem / "apps"
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy(png, target / "veilux-backend.png")
    installer = staging / "install-desktop-entry.sh"
    installer.write_text(LINUX_DESKTOP_INSTALLER, encoding="utf-8")
    installer.chmod(0o755)


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(out: Path):
    import PyInstaller.__main__
    tag, ver = system_tag(), version()
    system = tag.split("-")[0]
    work = ROOT / "build" / "pyinstaller"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    windows = []
    if system == "windows":
        windows_version_file(work / "version-info.txt", ver)
        windows = ["--icon", str(ICONS / "veilux.ico"), "--version-file", str(work / "version-info.txt")]
    PyInstaller.__main__.run([
        str(ROOT / "server.py"), "--name", NAME, "--onedir", "--console", "--noconfirm", "--clean",
        "--distpath", str(work / "dist"), "--workpath", str(work / "work"), "--specpath", str(work),
        # Data files PyInstaller cannot find by following imports: the public
        # suffix list snapshot (used offline), the CA bundle, and uvicorn's
        # protocol and loop modules, which it imports by name.
        "--collect-data", "tldextract", "--collect-data", "certifi", "--collect-submodules", "uvicorn",
        "--exclude-module", "tkinter", "--exclude-module", "pytest", "--exclude-module", "playwright",
        *windows,
    ])
    folder = f"{NAME}-{ver}-{tag}"
    staging = out / folder
    shutil.rmtree(staging, ignore_errors=True)
    shutil.copytree(work / "dist" / NAME, staging, symlinks=True)
    for name in ("LICENSE", "NOTICE"):
        shutil.copy(ROOT / name, staging / name)
    dists = runtime_distributions()
    copy_licences(dists, staging / "THIRD_PARTY_LICENSES")
    if system == "macos":
        macos_launcher(staging, ver)
    elif system == "linux":
        linux_icons(staging)
    (staging / "HOW-TO-START.txt").write_text(HOW_TO_START[system].format(version=ver, arch=tag.split("-")[1]),
                                              encoding="utf-8", newline="\r\n" if system == "windows" else "\n")
    (staging / "BUILD-INFO.txt").write_text("\n".join([
        f"VEILUX backend {ver} for {tag}",
        f"Commit: {os.environ.get('GITHUB_SHA') or git('rev-parse', 'HEAD')}",
        f"Built: {git('log', '-1', '--format=%cI')} (commit date)",
        f"Python {platform.python_version()} ({platform.platform()})",
        f"PyInstaller {metadata.version('pyinstaller')}",
        "", "Bundled libraries:", *[f"  {d.metadata['Name']}=={d.version}" for d in dists.values()], ""]), encoding="utf-8")
    if system == "windows":
        archive = out / f"{folder}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for path in sorted(staging.rglob("*")):
                z.write(path, Path(folder) / path.relative_to(staging))
    else:
        archive = out / f"{folder}.tar.gz"
        with tarfile.open(archive, "w:gz", compresslevel=9) as t:
            t.add(staging, arcname=folder)
    print(f"Built {archive}")
    print(f"Program: {staging / (NAME + ('.exe' if system == 'windows' else ''))}")
    return archive


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist")
