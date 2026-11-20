"""Builds the browser extension packages from extension/.

    python packaging/build_extensions.py [output folder, default dist]

Writes:
  veilux-<version>-chromium.zip   Chrome, Edge, Brave, Opera and Vivaldi
                                  (load unpacked from the extracted folder, or
                                  upload to the Chrome Web Store / Edge Add-ons)
  veilux-<version>-firefox.xpi    Firefox 140+, unsigned: Mozilla signs it
                                  when it is submitted to addons.mozilla.org

Both contain the files of extension/ exactly as committed: the manifest
already serves both browser families (Chromium uses background.service_worker,
Firefox background.scripts and browser_specific_settings), and it is the one
every test runs against. The archives are reproducible: entries are sorted,
and dates and permissions are fixed, so the same commit gives the same bytes.
"""
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "extension"
SKIP = {".DS_Store", "Thumbs.db", "desktop.ini"}


def build_time():
    """The commit time, so a rebuild of the same commit is identical."""
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        return int(subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True,
                                  text=True, check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        return 1767225600  # 2026-01-01


def check_manifest():
    manifest = json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    backend = re.search(r'^VERSION = "([^"]+)"', (ROOT / "server.py").read_text(encoding="utf-8"), re.M).group(1)
    if version != backend:
        sys.exit(f"The extension ({version}) and the backend ({backend}) versions differ.")
    referenced = {manifest["background"]["service_worker"], *manifest["background"]["scripts"],
                  manifest["action"]["default_popup"], *manifest["icons"].values(), *manifest["action"]["default_icon"].values()}
    missing = sorted(name for name in referenced if not (SOURCE / name).is_file())
    if missing:
        sys.exit("The manifest names files that do not exist: " + ", ".join(missing))
    if manifest["browser_specific_settings"]["gecko"]["id"] != "veilux-soc-assistant@veilux.local":
        sys.exit("The Firefox add-on ID changed; Mozilla treats a new ID as a different add-on.")
    return version


def write_archive(target: Path, stamp: int):
    files = sorted(p for p in SOURCE.rglob("*") if p.is_file() and p.name not in SKIP and "__pycache__" not in p.parts)
    date = time.gmtime(max(stamp, 315532800))[:6]  # ZIP dates start in 1980
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(SOURCE).as_posix(), date_time=date)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    return len(files)


def main(out: Path):
    version = check_manifest()
    out.mkdir(parents=True, exist_ok=True)
    stamp = build_time()
    for name in (f"veilux-{version}-chromium.zip", f"veilux-{version}-firefox.xpi"):
        count = write_archive(out / name, stamp)
        print(f"{out / name}  ({count} files)")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist")
