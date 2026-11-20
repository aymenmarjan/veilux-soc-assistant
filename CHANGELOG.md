# Changelog

All notable changes to VEILUX are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## 1.0.0 — first public release

* Browser extension for Chrome, Edge, Brave, Opera, Vivaldi (121+) and
  Firefox (140+), with a local Python backend.
* Configurable connections: tables and JSON on the page, immediate and
  search-job APIs, and the analyst's own browser sign-in, with optional
  templates for Splunk (the search on screen, or a search job), Microsoft
  Sentinel (KQL query, or an incident and its alerts), the Microsoft Defender
  portal (an incident and its alerts), Elasticsearch / OpenSearch / Wazuh
  (search, or a document from Discover, through the cluster's REST API),
  OpenSearch Dashboards / Wazuh dashboard (browser login) and IBM QRadar.
  Each template is tested against mock APIs that follow the vendor's API
  reference.
* Release packages: a Chromium ZIP and a Firefox XPI built from the same
  files, and a standalone backend (no Python needed) for Windows x64, Linux
  x64, macOS Intel and Apple silicon. The packaged backend keeps its key,
  lessons and cache in the user's own data folder, writes files whole, and
  explains a busy port. It carries the VEILUX icon: inside the Windows
  program, as a macOS app that opens it in Terminal, and as Linux icons with
  an optional application-menu entry. A separate workflow builds every package, starts,
  pairs and stops each backend, pairs the built extension with it, and
  records SHA-256 checksums.
* App sign-in with OAuth 2.0 client credentials, search jobs started with a
  form body, the platform's reason when a search fails, paged search-job
  results, and a warning when an API returns partial results.
* Local protection before anything is sent: credential detection, privacy
  masking with restorable markers, custom rules, and a review of uncertain
  values highlighted on the source page.
* AI analysis, follow-up questions and email reports per case, with Groq,
  DeepSeek, Together AI, OpenRouter, Gemini, Claude or your own
  OpenAI-compatible, Claude or Gemini endpoint.
* Threat intelligence from VirusTotal, AbuseIPDB and WHOIS/RDAP, and a case
  indicator list with checks, defanged copy and CSV export.
* Several cases side by side, each with its own inputs, notes, results and a
  record of everything that was sent.
* Backend access: only the paired extension. Every request needs a random
  backend key, which the extension receives once by entering the pairing code
  the backend shows at start-up; web pages, other extensions and other
  programs without the key are refused. The key file is readable only by
  your user account on Windows, Linux and macOS, checked at every start.
