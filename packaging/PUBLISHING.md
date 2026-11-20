# Publishing the VEILUX packages

The **Release packages** workflow (`.github/workflows/package.yml`) builds and
checks every package. It runs on pushes to `release/**` branches and `v*`
tags, or by hand: **Actions → Release packages → Run workflow**.

Its packages stay private build artifacts of this repository for 30 days.
Nothing is published by the workflow.

## What the workflow produces

Download the **veilux-release-packages** artifact from the workflow run. It
contains:

| File | For |
| --- | --- |
| `veilux-1.0.0-chromium.zip` | Chrome, Edge, Brave, Opera, Vivaldi (121+) |
| `veilux-1.0.0-firefox.xpi` | Firefox 140+ (unsigned until Mozilla signs it) |
| `veilux-backend-1.0.0-windows-x64.zip` | Windows 10/11, x64 |
| `veilux-backend-1.0.0-linux-x64.tar.gz` | Linux x64 with glibc 2.35+ |
| `veilux-backend-1.0.0-macos-x64.tar.gz` | macOS on Intel |
| `veilux-backend-1.0.0-macos-arm64.tar.gz` | macOS on Apple silicon |
| `SHA256SUMS.txt` | SHA-256 of each file above |

The **safari-experimental** artifact holds an unsigned Xcode project and the
converter's report. It is not a release package (see the end of this file).

## Before publishing

1. Check that the run passed on the exact commit you will publish. These jobs
   must be green:
   - the extension lint;
   - the four backend builds, each with its start, pair, use, stop and restart
     check;
   - the pairing check between the built extension and the built backend;
   - the checksums.
2. Verify the downloaded files:
   - Linux and macOS: `sha256sum -c SHA256SUMS.txt`
   - Windows PowerShell: `Get-FileHash <file> -Algorithm SHA256`, then compare
     with `SHA256SUMS.txt`.

## Firefox (addons.mozilla.org)

The add-on ID is `veilux-soc-assistant@veilux.local`. Keep it: Mozilla treats a
new ID as a different add-on.

- **Listed on AMO.** In the AMO Developer Hub, submit
  `veilux-1.0.0-firefox.xpi` as a new add-on, Firefox desktop only.
  - The code is not minified or generated, so no separate source code
    package is needed.
  - Answer the review notes about the page scripts as agreed before: they are
    the analyst's own code, run in the page, and off unless configured.
- **Self-distributed (unlisted).** Sign the same file without listing it:
  1. Create API credentials under **Tools → Manage API Keys** on AMO.
  2. Run:
     ```
     npx web-ext sign --channel=unlisted --source-dir <the extracted XPI> \
       --api-key=$AMO_JWT_ISSUER --api-secret=$AMO_JWT_SECRET
     ```
  3. Publish the signed `.xpi` that Mozilla returns, not the unsigned one.

## Chrome, Edge, Brave, Opera and Vivaldi

- **Chrome Web Store** (also used by Brave and Vivaldi):
  1. In the developer dashboard, upload `veilux-1.0.0-chromium.zip`.
  2. Give each permission's justification.
  3. Disclose website-content access in the privacy section: VEILUX reads
     pages only when the analyst extracts from them.
- **Microsoft Edge Add-ons:** in Partner Center, upload the same ZIP.
- **Opera add-ons:** upload the same ZIP, or point users to the Chrome Web
  Store listing.
- **Without a store:** users extract the ZIP and choose **Load unpacked** on
  the browser's extensions page, with developer mode on.

## The backend (a GitHub release on the public repository)

1. Push the release commit to `aymenmarjan/veilux-soc-assistant`, following the
   migration guide.
2. Let **Release packages** run there.
3. Create the release:
   - tag the commit `v1.0.0`;
   - create a GitHub release from the tag;
   - attach all files from **veilux-release-packages**, including
     `SHA256SUMS.txt` and the signed Firefox XPI.
4. In the release notes:
   - the minimum systems (Windows 10/11 x64; macOS Intel and Apple silicon;
     Linux x64 with glibc 2.35+);
   - that the backend is unsigned (below);
   - how to verify `SHA256SUMS.txt`.

**Code signing (optional; removes the security warnings).**
- **Windows.** Sign `veilux-backend.exe` with an Authenticode certificate
  before zipping:
  ```
  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 veilux-backend.exe
  ```
  Without it, SmartScreen asks users to choose **More info → Run anyway**.
- **macOS.** Sign every binary with a Developer ID Application certificate,
  using the hardened runtime, then notarize:
  ```
  codesign --force --options runtime --timestamp --sign "Developer ID Application: …" <binaries>
  xcrun notarytool submit <zip> --apple-id … --team-id … --wait
  ```
  Without it, users clear the quarantine flag as `HOW-TO-START.txt` explains.
- **Linux:** none needed. The SHA-256 checksums are the integrity check.

Signing changes the files, so recompute `SHA256SUMS.txt` after signing.

## Safari (not yet a supported browser)

Safari extensions ship inside a signed macOS app. The experimental job shows
how far conversion and an unsigned build get. To publish:
1. Join the Apple Developer Program.
2. Open the generated Xcode project and set your team and bundle identifier.
3. Test VEILUX in Safari: background service worker, scripting, cookies, and
   pairing with the backend.
4. Archive the app, then distribute it through the Mac App Store or as a
   notarized app.

Until it has been tested in Safari, do not list Safari as supported.
