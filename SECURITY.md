# Security

VEILUX handles security logs, credentials and API keys, so security reports are
welcome and taken seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**
([direct link](https://github.com/aymenmarjan/veilux-soc-assistant/security/advisories/new)). Do not open a public
issue for a vulnerability, and never include real logs, keys, IP addresses or
customer data in a report; synthetic values that reproduce the problem are
enough.

Please include the VEILUX version (Settings → Backend → **Check backend** shows it), the
browser and its version, and the steps to reproduce. You should get a first
answer within a week. Fixes are released as soon as they are ready, and the
reporter is credited unless they prefer otherwise.

Only the latest release is supported with security fixes.

## How VEILUX is meant to be run

VEILUX has two parts: the browser extension, and a backend (`server.py`) that
runs on the analyst's own computer. Knowing what each part trusts helps to
judge whether something is a vulnerability.

### What leaves the computer

| Destination | What it receives | When |
| --- | --- | --- |
| The AI service you choose | The case's logs, statistics and notes **after** local protection: credentials are masked, and with privacy masking on, IPs, users, hosts, domains and your own keywords are replaced by markers | Analyze, Ask, Report |
| VirusTotal, AbuseIPDB, RDAP | One indicator per request (a public IP, domain, URL or hash), never the log | Threat-intelligence lookups you enable |
| Your SIEM/SOAR | The requests your saved connections define | Extraction and connection tests |
| The token address of a connection with app sign-in (for example Microsoft Entra ID) | The app's client ID, client secret and scope, to obtain an access token | Before that connection's first request, and when its token expires |
| OpenRouter | Nothing about your cases; a public model list is downloaded | Find free models |

The **Sent** tab of each case records every AI request and lookup exactly as it
was sent.

Local protection is a strong safeguard, not a guarantee. A secret with no
recognizable format, label or context can go undetected; use **Hide selected
text** for such values, and choose an AI service whose data handling you accept.

### The backend

* It listens on `127.0.0.1:8000` by default, so only this computer can reach it.
* It answers only the VEILUX extension: requests from web pages (any other
  `Origin`) are refused, and so are browser requests that reach it under an
  unknown host name (DNS rebinding).
* **Every request needs the backend key** (sent as `X-Veilux-Token`, compared
  in constant time), except `GET /health` (status and version only) and
  pairing. This keeps other browser extensions, which may call `localhost`
  with their own extension origin, and other programs away from the backend.
  The key is random (256 bits), created on first start in `veilux_backend.key`,
  or taken from `VEILUX_TOKEN` (at least 16 characters, or the backend does not
  start).
* **Only your user account can read the key file.** On Linux and macOS it has
  mode `0600` and must belong to you; macOS also drops any access list the
  folder passes on. On Windows it stops inheriting the folder's permissions and
  grants access to your account alone (with `icacls`, part of Windows). Each
  start checks this and fixes a file with looser permissions, for example one
  copied from elsewhere; if that is not possible, the backend does not start.
  Keep the backend's folder writable only by you.
* **Pairing** gives the key to the extension: the backend prints a code at
  start-up, valid for 15 minutes, accepted only from this computer (not through
  a proxy), and disabled after 5 wrong tries. The extension stores the key in
  its own storage, which other extensions cannot read.
* From other computers, enter the `VEILUX_TOKEN` value in **Settings → Backend
  → Backend key**, and set `VEILUX_ALLOWED_HOSTS` to the name they use for the
  backend.
* A request relayed by a reverse proxy on the same computer counts as remote
  when the proxy adds a `Forwarded`, `X-Forwarded-For` or `X-Real-IP` header.
  A proxy that sends none makes remote requests look local, which matters only
  for pairing: every request still needs the key.
* The backend serves plain HTTP; across a network, put it behind a TLS reverse
  proxy or use it only on a trusted network.
* Besides the key, it writes two files: `threat_intel_cache.json` (lookup
  results for 24 hours, keyed without API keys) and `training_feedback.json`
  (your lessons). Neither holds API keys.
  * Run from source, all three files are in the folder the backend runs
    from, and `.gitignore` excludes them from Git.
  * The packaged backend keeps them in your own application-data folder:
    `%LOCALAPPDATA%\VEILUX` on Windows, `~/Library/Application Support/VEILUX`
    on macOS, and `~/.local/share/veilux` on Linux (created with mode 0700).
  * `VEILUX_DATA_DIR` chooses another folder.
  * Files are replaced whole, so stopping the backend mid-write cannot leave
    half a file. An unreadable file is set aside as `.unreadable`, and the
    backend starts without it.
* The packaged backend is not code-signed yet. Check its SHA-256 checksum
  against the release's `SHA256SUMS.txt` before running it.

### The extension

* API keys, SIEM credentials and the backend token are stored in the browser's
  extension storage on this computer, unencrypted, like other extensions'
  settings. Anyone with access to the browser profile can read them. A separate
  browser profile for SOC work is a good idea.
* App sign-in secrets are sent only to a verified `https://` token address,
  even for a connection that skips certificate checks for its API. The access
  tokens they return stay in the backend's memory and are never stored.
* **Settings → Backup → Export** leaves keys, passwords, client secrets and tokens out unless
  you tick **Include API keys in export**. Treat a file exported with keys as a secret.
* It needs access to all sites because SIEM and SOAR consoles live at addresses
  only you know. It reads a page only when you extract from it, review
  credentials on it, or a connection you saved reads it.
* **Custom page scripts.** A connection can use your own script to read an
  unusual page. That script runs inside the SIEM page with your sign-in, so it
  can do anything you can there. VEILUX asks before importing settings that
  contain one. Only use scripts you have read and trust.
* A connection can switch off certificate checking for its API. Use that only
  for a lab, and prefer **More options → Organization CA certificate**.

## Out of scope

* Findings that need the attacker to already control the analyst's computer,
  browser profile or backend folder.
* A secret in an unrecognizable format reaching the AI service when it was not
  hidden by hand (see above), unless a documented rule should have caught it.
* Behaviour of third-party AI, threat-intelligence or SIEM services.
