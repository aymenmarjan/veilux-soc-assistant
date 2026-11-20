# Testing VEILUX in every browser

VEILUX is one Manifest V3 extension for Chromium-based browsers (Chrome,
Edge, Brave, Opera, Vivaldi) and Firefox. The two families run the same code
but differ in what they allow, so a change that works in Chrome can still
break in Firefox. This page lists the checks to run before a release, from
fully automatic to by hand.

## Supported versions

| Browser | Minimum | Why |
| --- | --- | --- |
| Chrome, Edge, Brave, Vivaldi | 121 | First version that accepts the manifest's `background.scripts` (used by Firefox) next to `service_worker` |
| Opera | 107 | Chromium 121 |
| Firefox (desktop) | 140 (current ESR) | Session storage, scripts in the page's own world, and the data-collection declaration that addons.mozilla.org requires |
| Safari | Not packaged | Needs conversion with Xcode on macOS; see the README |

The minimums are declared in `extension/manifest.json`
(`minimum_chrome_version`, `browser_specific_settings.gecko.strict_min_version`),
so older browsers refuse to install VEILUX instead of half-working.

## 1. Automatic checks (a minute, no browser needed)

```bash
cd tools/browser-check
npm install
npm run check
```

* **Firefox add-on lint** (`web-ext lint`): the checks addons.mozilla.org
  runs on upload, including manifest keys and APIs that the declared Firefox
  version lacks. It must report 0 errors. Three warnings are expected and
  listed as "known and reviewed" (Chromium's service-worker key, the custom
  page script, and Firefox for Android); any other warning, such as a new
  `innerHTML` assignment, fails the check. Put markup in pages with
  `setHTML` (`extension/html.js`) and escape every value with `escapeHtml`.
* **Web API compatibility** (`eslint-plugin-compat`): every web API the
  extension calls, compared with the browsers in
  `tools/browser-check/eslint.config.mjs`. Keep that list in step with the
  manifest minimums.

## 2. The test suite in each browser engine

The UI tests open the popup and Settings pages with a simulated extension API,
so the same tests run in Chromium, Firefox and WebKit:

```bash
pip install -r requirements-test.txt
python -m playwright install chromium firefox webkit
python -m pytest tests                                   # Chromium (default)
VEILUX_TEST_ENGINE=firefox python -m pytest tests        # Firefox engine
VEILUX_TEST_ENGINE=webkit python -m pytest tests         # Safari's engine (informative)
```

On Windows PowerShell, set the engine with `$env:VEILUX_TEST_ENGINE="firefox"`
before running pytest.

The GitHub workflow runs the suite in Chromium and in Firefox's engine on every
push and pull request; both must pass. It also checks the backend key file's
permissions on Windows, macOS and Linux.

These runs catch layout, CSS and JavaScript differences between engines. They
do not load the real extension in Firefox: the tests that do
(`test_native_*`) load the unpacked extension in Chromium, with its real
Manifest V3 security rules, and are skipped for the other engines.

## 3. The real extension, by hand

Run the real extension in a clean profile:

```bash
cd tools/browser-check
npm run firefox      # a fresh Firefox profile with VEILUX loaded
npm run chromium     # the same in Chromium
```

Then walk through this list in Firefox and in one Chromium browser. Each
line names what tends to differ between them.

| Step | What to check | Why it can differ |
| --- | --- | --- |
| Install | No warning banner about site access in the popup | Firefox lets people switch off site access per add-on; VEILUX then shows **Allow site access** |
| Settings → Backend → Pair with the code the backend printed, then Check backend | "Paired with the backend", then "… this browser is paired with it" | Firefox and Chromium handle requests to `localhost` (and the custom key header) differently |
| Extract logs from a SIEM page | Logs appear | Page scripts and permissions differ |
| Extract statistics | A query appears, opens and closes | Background work runs in a service worker (Chromium) or event page (Firefox) |
| Close the popup during extraction, reopen | The result arrives | Background lifetime differs |
| Analyze with a value that needs review | Review stage, red highlights on the SIEM page | Highlighting uses the CSS Highlight API, or a canvas fallback |
| Click the page, reopen the popup | Highlights still on the page, **Continue review** offered | Popups close on focus loss in both, but timing differs |
| Ask a question, generate a report | Answer and email appear | |
| Report → Copy for email, paste in your mail client | Formatted email, no subject line | Clipboard rules differ |
| Right-click a page → VEILUX: Extract logs | A popup window opens on that tab | Context menus and windows |
| Settings → Backup → export and import | Settings come back | File download and upload |
| Dark mode | Popup and Settings both switch | |

### Popup size

The popup asks for 720x600. What it gets differs:

| Browser | What it opens |
| --- | --- |
| Chrome, Edge, Brave, Opera | Exactly 720x600 on a normal screen; shorter when the screen has less room |
| Firefox | The natural size of the page's content, up to 800x600 |

Firefox does not read the page's declared size: it measures the content. So
`<html>` and `<body>` both carry 720x600 in pixels (`styles.css`). Content
that is only `position: fixed` measures as zero (Firefox then opens an empty
sliver), and content without a fixed size measures at whatever its text needs
(Firefox then opens it narrow). `test_popup_has_the_natural_size_firefox_measures`
does Firefox's measurement in Chromium.

The visible content is pinned to the window the browser actually opened
(`.popup-page .container` in `ui.css` is `position: fixed`), so it also fills
a popup a browser opens smaller on a small screen, down to about 380px wide. When checking a browser by hand, open the popup with the browser window
maximized and again with a small window pushed to the edge of the screen: in
both, nothing may be cut off, no blank strip may show on the right, and the
action bar must sit at the bottom edge.
`test_native_toolbar_popup_opens_at_the_size_it_asks_for` opens Chrome's real
toolbar popup, and `test_popup_fills_whatever_window_the_browser_opens`
covers the other sizes.

A connection that uses **a custom page script** runs it in the page itself
(Manifest V3 does not let extensions turn text into code). On pages whose
security policy forbids that, the popup says so; use the table, JSON or API
reader for those pages.

## 4. Before publishing on a store

* **Chrome Web Store / Edge Add-ons / Opera add-ons**: upload a zip of the
  `extension/` folder. Edge and Opera accept the Chrome package unchanged.
* **addons.mozilla.org**: upload the same zip, for Firefox desktop. Before the
  first upload, check:
  * the add-on ID (`browser_specific_settings.gecko.id`,
    `veilux-soc-assistant@veilux.local`) is final: it can never change after the
    first listing, and AMO refuses an ID that is already taken;
  * `version` in `manifest.json` is higher than any version uploaded before;
  * the data-collection declaration is still right: the manifest declares
    `websiteContent`, because log text read from pages is sent to the AI and
    threat-intelligence services the analyst configures;
  * `npm run check` reports 0 errors. Its three known warnings need a note to
    the reviewer: Chromium's `service_worker` key (ignored by Firefox), Firefox
    for Android (not a supported platform; choose desktop only when uploading),
    and `DANGEROUS_EVAL` in `connector_client.js`, the optional custom page
    script, which runs code the analyst writes themselves in the page's own
    world, never code downloaded from elsewhere;
  * the code is not minified or bundled, so no separate source upload is needed.
* Run section 1 and section 2 with `chromium` and `firefox` after the last
  change, and section 3 at least once per release.
