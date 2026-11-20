# Contributing to VEILUX

Thanks for helping. Bug reports, fixes, new SIEM presets and documentation are
all welcome.

## The one rule: no real data

VEILUX exists to keep security data private, and its repository must too.
Never put real logs, IP addresses, host or user names, domains, customer or
company names, API keys or tokens in code, tests, screenshots, issues or pull
requests. Use:

* IP addresses from the documentation ranges: `192.0.2.x`, `198.51.100.x`,
  `203.0.113.x`, or private ranges such as `10.x.x.x`;
* `example.com`, `example.org`, `example.net` and `.test`, `.local` names;
* obviously synthetic keys (`"ghp_" + "A" * 36`, `synthetic-key`), built in the
  test rather than written out, so secret scanners stay quiet.

## Set up

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements-test.txt
python -m playwright install chromium
python server.py
```

Load the `extension/` folder as an unpacked extension (see the README), and
pair it under **Settings → Backend** with the code the backend prints when it
starts (and set the address there if you changed its port). The test suite
uses its own fixed key and never writes a key file.

## Tests

```bash
python -m pytest tests                       # backend and UI tests (Chromium)
python tests/test_connectors.py              # connector engine against a mock SIEM
for f in tests/test_*.js; do node "$f"; done # extension modules in Node
cd tools/browser-check && npm ci && npm run check   # Firefox add-on lint, web API compatibility
```

UI tests open the real popup and Settings pages with a simulated extension
API, and every external service is mocked. `VEILUX_TEST_ENGINE=firefox` runs them
in Firefox's engine; see [docs/BROWSER_TESTING.md](docs/BROWSER_TESTING.md).
A change should come with a test that fails without it.

## Code guidelines

* **Extension pages:** no `innerHTML` and no `eval`. Build markup with `setHTML`
  (`extension/html.js`) and escape every value with `escapeHtml`. The add-on
  lint fails on new warnings.
* **Cross-browser:** the same code runs in Chromium and Firefox. Use `browser.*`
  APIs and check `npm run check` after adding a web API.
* **Protection first:** anything new that sends data out (an AI request, a
  lookup, a SIEM request) must go through the existing protection pipeline and
  appear in the case's **Sent** record.
* **Comments** explain why the code is the way it is, for the next reader. They
  do not narrate the change history; that belongs in the pull request.
* Keep the popup uncluttered: one stage shows one thing at a time.

## Pull requests

* One topic per pull request, with a short description of the problem and how
  you checked the fix.
* Make sure the tests and browser checks pass.
* By contributing, you agree that your contribution is licensed under the
  project's [Apache License 2.0](LICENSE), as section 5 of the licence describes.

Security problems: please follow [SECURITY.md](SECURITY.md) instead of opening
an issue.
