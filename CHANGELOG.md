# Changelog

All notable changes to VEILUX are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## 1.0.2

### Fixed

* **Reasoning models returned no analysis on long prompts.** Built-in
  providers were sent a fixed limit of 4,000 output tokens (8,192 for Gemini).
  Reasoning models such as DeepSeek's count their thinking in that limit, so
  they could use all of it before writing an answer: the request showed HTTP
  200 and "Done" with nothing to read. The default is now 16,384 tokens, or the
  model's own maximum when its provider reports a lower one, and it can be
  changed per provider.
* **No answer is never reported as done.** An empty, whitespace-only or
  reasoning-only reply, or one that reached the output limit before any answer,
  now fails with a message that says what happened and which setting to
  change, and the record of what was sent shows it as failed. An answer cut off
  at the limit is shown with a note, and recorded as cut off; a report cut off
  before its end says so instead of blaming the model. This applies to Analyze,
  Ask and Report alike. Nothing is retried, and no limit is raised without the
  analyst.
* **Answers are read in full, and only the visible part.** Gemini answers in
  several parts are joined (only the first part was read); Gemini thought
  parts, Claude thinking blocks, `reasoning_content` and `<think>` sections are
  never part of the analysis. Gemini safety and other blocks, and Claude
  refusals, are explained.
* **Claude:** no temperature is sent, because current Claude models refuse any
  value other than their default.
* **Groq** receives the limit as `max_completion_tokens`, its current name.
* A model's refusal of the output limit gets its own message, and OpenRouter
  errors no longer repeat the service's raw reply.

### Added

* **Advanced settings per provider** (Settings → Providers and API keys →
  provider → Advanced): **Maximum output tokens** for every built-in provider;
  **Thinking** and **Reasoning effort** for DeepSeek and Claude models whose
  model list reports them, with only the levels the model supports. **Load
  models** now keeps each model's reported output limit and reasoning options.
  Saved 1.0.1 settings keep working: a model chosen before 1.0.2 gets the
  default limit and no reasoning settings until it is chosen again from the
  list. The settings are included in exports.

### Changed

* **Settings → Providers and API keys** is a list of collapsible cards, one
  per provider, each showing whether it has a key and a model. A card holds the
  API key, the model choice (Load models or a typed ID), **Test connection**
  and the collapsed **Advanced** settings. **Test All APIs** is unchanged.
* Settings: a control reached with the keyboard is no longer left behind the
  Save settings bar, and in a short window the bar stays at the end of the
  page instead of covering it.

### Security

* Connection checks, extraction and model-list errors repeat only messages
  written by VEILUX and fields of the service's structured error. Exception
  text, non-JSON and HTML error bodies are no longer shown, and any credential
  VEILUX sent (header, cookie, token or Basic user and password) is replaced
  with `[hidden]` if a service echoes it, however short it is (CodeQL alert
  32). The same applies to OpenRouter errors inside a successful reply and to
  a search job's ID, status and error reason.

## 1.0.1

### Fixed

* **AI models are no longer built in.** A fixed model ID stops working when a
  provider retires it (Groq: "The model llama-3.3-70b-versatile does not exist
  or you do not have access to it"). Groq, DeepSeek, Together AI, Gemini and
  Claude now use the model chosen in Settings → Providers and API keys:
  **Load models** reads the provider's own model list with the API key only
  (no logs, notes or prompts), and a model ID can also be typed. An analysis
  without a chosen model stops before anything is sent. A model the provider
  no longer offers, a refused key and rate limits get their own clear
  messages, and VEILUX never switches to another model by itself.
  **Test All APIs** checks each key and the chosen model through the model
  list instead of sending a prompt (the Gemini key is no longer put in the
  address). Custom models get **Load models** for OpenAI-compatible (including
  Ollama and LM Studio), Claude and Gemini URLs. OpenRouter is unchanged.
* **Defanging URLs with host names.** `https://www.google.com/` now becomes
  `hxxps://www[.]google[.]com/`, like IP addresses already did. The scheme
  keeps its letter case (`hxxp`, `HXXP`), every dot in a URL's host, e-mail
  domains and bare domain names (with a real public suffix) is bracketed, and
  paths, query strings and file names such as `cmd.exe` are left alone.
  Defanging twice changes nothing; refang restores the exact original and
  still reads the `hXXp` form of 1.0.0. The popup's offline fallback uses the
  same scheme form.
* **Pasted logs with `---LOG SEPARATOR---` counted as one log.** Typing or
  pasting into the log box now splits on the separator exactly as the
  analysis request does, so the log count, the case summary, statistics from
  captured logs and indicators see the same separate logs the AI receives.
  Text without a separator is kept exactly as typed. A new **Insert log
  separator** button under the log box adds a separator at the cursor.
  Extracted SIEM/SOAR logs are unchanged.

### Tests

* The suite runs on Windows as on Linux and macOS: the data-folder test no
  longer simulates another system by patching `sys.platform` (the folder for
  each system is computed by `data_dir_for`, the same on any computer); the
  backend's output is read as UTF-8 instead of the Windows code page; the mock
  SIEM listens on a port the system chooses instead of 9401; and the statistics
  UI tests wait until the popup has finished starting (`data-ready`) instead of
  racing it.

### Security

* Connector requests can no longer be moved by data read while working. Values
  from pages, search IDs and context fields from API responses always fill one
  encoded path segment, a value of `.` or `..` stops the request, and every
  built address is checked to stay on the configured API address and its path.
  The legacy single-record mode now builds addresses the same way.
* The API address, the app sign-in token address and custom model addresses
  are checked: `http://` or `https://` only, no user name or password in a
  connector's API address, and link-local or cloud instance-metadata addresses
  (such as `169.254.169.254`, including its decimal and hexadecimal spellings)
  are refused. Private and local addresses keep working. Redirects are never
  followed.
* Link patterns are matched with a time limit, so a pattern with nested
  repetition cannot freeze the backend on a crafted link; patterns, links and
  the number of links per request are capped.
* Error responses no longer include unexpected exception text; it stays in
  the backend window.
* The in-memory app sign-in token cache is keyed with an HMAC under a random
  per-start key instead of a plain SHA-256 of the client secret.
* Threat-intelligence lookups encode the indicator as one path segment.

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
