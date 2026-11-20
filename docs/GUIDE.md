# VEILUX — Architecture & Concepts Guide

A beginner-friendly walkthrough of how this tool works, why each piece exists,
and what every technology in it does. Written to be readable before you know
the vocabulary — each concept is explained the first time it appears.

For adding your own AI model, see [your own AI models](CUSTOM_MODELS.md).
Model defaults, connection testing and optional response settings are explained
there using the current Settings labels.

---

## 1. The big picture

The tool is **three programs cooperating**:

```
┌────────────────────┐         ┌─────────────────────┐         ┌──────────────────┐
│ Browser extension   │  HTTP   │ Local backend        │  HTTPS  │ AI provider       │
│ (JavaScript, runs   │ ──────► │ (Python + FastAPI,   │ ──────► │ (Groq, Claude,    │
│ inside your browser)│ ◄────── │ runs on your machine)│ ◄────── │ Gemini, ...)      │
└────────────────────┘         └─────────────────────┘         └──────────────────┘
        │
        ▼
  The log viewer, SIEM or case-management page open in your browser
```

- The **extension** lives in the browser because that's where your session
  with your security tools lives. It can see the page you're looking at, read
  your logged-in cookies, and make requests *as you*.
- The **backend** (`server.py`) runs on `localhost:8000` (change it with
  `--port` and Settings → Backend) — your own machine,
  not a server on the internet. It exists for two reasons:
  1. **Privacy**: it swaps sensitive values (IPs, usernames, hostnames) for
     placeholders *before* anything is sent to an AI company, and swaps them
     back in the answer. The AI never sees your real infrastructure.
  2. **Capability**: some things a browser page can't do — like calling an
     API with a secret token, trusting a private certificate authority, or
     running a multi-step polling loop — a local Python process can.
- The **AI provider** is interchangeable. The backend speaks each provider's
  API dialect so the rest of the tool doesn't have to care which one you pick.

Where the logs come from is up to you: a table or JSON on any page, an API, or
your own script. Platform templates exist for a few common products (see
section 3), but none of them is required.

---

## 2. Concepts glossary (read this once, everything else makes sense)

**HTTP request / response** — the language of the web. A request says
"METHOD + URL + headers + optional body" (e.g. `GET /api/alerts/42`),
the server answers with a status code (`200` = OK, `401` = bad credentials,
`404` = not found) and a body.

**JSON** — the text format almost every modern API speaks:
`{"id": 42, "status": "OPEN"}`. Both your SIEM's responses and this tool's
internal messages are JSON.

**REST API** — a web service organized around URLs-as-things:
`/api/alerts/42` *is* alert 42; `GET` reads it. Security tools expose REST
APIs so machines (like this tool) can do what the UI does.

**Endpoint** — one URL+method a server answers on. `server.py` defines
endpoints like `POST /analyze` and `POST /fetch-siem-logs`.

**FastAPI** — the Python library used to build the backend. You write a
Python function, decorate it with `@app.post("/analyze")`, and FastAPI turns
it into an endpoint: it parses the incoming JSON, validates it against a
declared shape (a *Pydantic model* — see `SiemFetchRequest` in server.py),
and serializes your return value back to JSON.

**CORS, the origin check and pairing** — browsers block a page on site A from
reading site B unless B allows it. The backend refuses web pages by their
origin, and refuses everything else (other extensions included) unless the
request carries the backend key, which the extension receives once by pairing
(see [SECURITY.md](../SECURITY.md)).

**Browser extension anatomy** (all in `extension/`):
- `manifest.json` — the extension's ID card: name, version, and crucially
  its **permissions** (what browser powers it may use: read tabs, inject
  scripts, read cookies, add context-menu items).
- `popup.html` / `popup.js` — the little window when you click the icon.
  Important: its whole JavaScript world is **destroyed the instant it
  closes**. That's why long work is handed elsewhere.
- `background.js` — a **service worker**: an invisible script the browser
  wakes when needed. It survives the popup closing, so AI analysis and
  extraction run there, and it owns the right-click context-menu item.
- `content.js` — a script the extension **injects into web pages** to read
  or click their DOM, for example a search page's Inspector panel.
- `browser.storage.local` — the extension's private key-value store; where
  settings, connections, and results live. Nothing is synced anywhere.

**DOM** — the live tree of elements behind a rendered page. A **CSS
selector** (like `div.links a[href]`) is a pattern for finding elements
in it. Connections use selectors when data is only reachable through the UI.

**Regex (regular expression)** — a pattern language for text. This tool
leans on one feature: **named capture groups**. The pattern
`/alerts/(?<alert_id>\d+)` says "find `/alerts/` followed by digits, and
*save those digits under the name* `alert_id`". Whatever names your regex
captures become the `${alert_id}`-style **placeholders** available in every
template of that connection. That's the core trick that makes connections
generic: *the regex decides the vocabulary, the templates use it.*
(One syntax note: JavaScript writes `(?<name>...)`, Python writes
`(?P<name>...)` — the tool accepts either and translates.)

**Template** — a string with `${placeholders}` filled in at runtime.
`/api/alerts/${alert_id}` + `{alert_id: "42"}` → `/api/alerts/42`.

**Dotted response path** — where to find the data inside a JSON response.
`data.events` means: take key `data`, then `events`. This exists because
every product puts its results somewhere different.

**Auth types** — ways a request proves who you are:
- **Browser session**: the session your browser already has from logging in.
  Free, but expires when your session does.
- **Basic**: username+password encoded into an `Authorization` header.
- **Header token**: a long-lived secret in a header, such as
  `Authorization: Bearer ...` or a vendor-specific header. Best for machine
  access; issued by an admin, revocable, scoped by permissions.
- **App sign-in (OAuth 2.0 client credentials)**: a registered app proves who
  it is with a client ID and secret, and receives a short-lived access token
  for one API. The backend asks for the token and renews it when it expires.
  Microsoft's APIs work this way.

**Synchronous vs asynchronous search** — two shapes of search API:
- Some APIs answer a query *in the same request* → one call, done.
  ("single request" mode)
- Others answer "job accepted, id = abc-123". You then **poll** (ask "done
  yet?" every couple of seconds) until the job reports it has finished, then
  fetch the results in a third call. ("search job" mode)
  This create → poll → results pattern is everywhere in engineering, which is
  why one generic executor in VEILUX handles every search-job API.

**Sanitization design** (worth understanding deeply — it's the tool's most
defensible engineering decision): values are replaced with placeholders like
`⟦USER#1⟧` wrapped in rare Unicode brackets that never occur naturally in
logs, so re-substitution can't corrupt anything. The mapping
placeholder↔real-value never leaves your machine; the AI answers *in
placeholders* and the backend restores the real values locally.

---

## 3. Connections across platforms

The [connection setup guide](CONNECTOR_SETUP.md) walks through the editor.
Each connection answers a few questions: which website, where the logs are
(a page table, page JSON, an API request, a search page's Inspector panel or a
script), and for APIs, where each `${value}` in the request comes from (the
page address, links on a page, text or an attribute, or a fixed value) and how
to sign in.

Every connection uses the same reader for Settings preview and popup extraction.
Page tables and JSON are read in the browser. API reads run in the signed-in tab
(browser login on the same website) or through the local backend. Blank fields
are never filled with built-in values.

**Platform templates** fill in a starting configuration, based on each vendor's
public API reference:
- Splunk (the search on screen, or a new search job);
- Microsoft Sentinel (a KQL query, or an incident and its alerts);
- the Microsoft Defender portal (an incident and its alerts);
- Elasticsearch, OpenSearch and the Wazuh indexer (a search, or a document
  from Discover);
- OpenSearch Dashboards and the Wazuh dashboard (browser login);
- IBM QRadar (an offense and its events).

They are editable examples, not automatic support for every vendor release.
Any other product with a page table, page JSON or a JSON API can be set up by
hand. The [connection setup guide](CONNECTOR_SETUP.md#platform-templates)
describes each template's requests and limits.

Statistics use the chosen record source, the logs already captured, or the
current search in an Inspector panel. Page samples cannot include rows that the
page has not rendered; saved API requests do not automatically inherit the
page's current filters. Unknown totals and record limits are reported
explicitly.

---

## 4. Walkthrough: an API connection with a search job

This example uses a fictional SIEM at `https://siem.example.com` whose alerts
open at `https://siem.example.com/alerts/<id>` and whose search API works as a
search job.

1. **Get a token** (once) from the SIEM, with permission to read alerts and run
   searches.
2. **Create the connection**: extension Settings → Connections → *Add a
   connection*. Name it, and enter `https://siem.example.com` as the website.
   Choose **An API request**, and under *How the API answers* choose **It
   starts a search job, then returns the results when the job finishes**:
   - start the search: `POST /api/searches` with the query in a URL parameter;
   - the job ID is at `id` in the answer;
   - check the status at `/api/searches/${job_id}` until `status` is `DONE`;
   - read the results at `/api/searches/${job_id}/results`, records at `events`.
3. **Request values**: add *The page address* with the pattern
   `https://siem.example.com/alerts/{alert_id}`, and use `${alert_id}` in the
   search. Optionally, **Also read a case summary** fetches the alert itself,
   and its fields become `${context.<field>}` in the search, for example to
   limit the search to the alert's own time range.
4. **Sign-in**: choose *API key or access token* and paste the token.
5. **Run the backend**: `python server.py` (search jobs go through it).
6. **Extract**: open an alert → click the extension → **Extract**. You get the
   alert record followed by its events.

What the tool does underneath, in API calls:

```
GET  /api/alerts/42                       ← optional context record
POST /api/searches?query=...              ← create the search job
GET  /api/searches/<job_id>               ← poll until finished
GET  /api/searches/<job_id>/results       ← fetch the events
```

**Pages in toolbar-less windows.** Some consoles open results in popup windows
without a toolbar, where the browser hides extension icons. **Right-click the
page → "VEILUX: Extract logs from this page"** opens the VEILUX popup pinned to
that exact tab.
