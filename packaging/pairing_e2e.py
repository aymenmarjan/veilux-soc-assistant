"""The built extension pairs with the built backend, in a real Chromium.

    python packaging/pairing_e2e.py <veilux-…-chromium.zip> <backend program>

Loads the extension from the release ZIP (as "Load unpacked" does after
extracting it), starts the packaged backend, enters its pairing code in
Settings -> Backend, and checks that:
- the key is stored in the extension and matches the backend's key file;
- "Check backend" reports the browser as paired;
- requests the extension signs reach the backend (CORS and origin checks
  included), and local protection answers;
- without the key, the same request is refused.
Needs Playwright with Chromium (pip install playwright; playwright install chromium).
Extensions load only in full Chromium (channel "chromium"), not in Playwright's
default headless shell.
"""
import os
import sys
import tempfile
import zipfile

from playwright.sync_api import expect, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smoke_test import Backend, check, free_port  # noqa: E402


def main(extension_zip, program):
    with tempfile.TemporaryDirectory(prefix="veilux-e2e-") as root:
        extension = os.path.join(root, "extension")
        with zipfile.ZipFile(extension_zip) as archive:
            archive.extractall(extension)
        data_dir = os.path.join(root, "data")
        port = free_port()
        backend = Backend([program], port, data_dir)
        try:
            code = backend.wait_for(r"Pairing code: ([A-Z0-9]{4}-[A-Z0-9]{4})", 120).group(1)
            address = f"http://localhost:{port}"
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch_persistent_context(
                    os.path.join(root, "profile"), channel="chromium", headless=True, ignore_default_args=["--disable-extensions"],
                    args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}"])
                try:
                    worker = browser.service_workers[0] if browser.service_workers else browser.wait_for_event("serviceworker", timeout=30000)
                    extension_id = worker.url.split("/")[2]
                    check("the extension from the ZIP loads and starts its service worker", bool(extension_id))
                    page = browser.new_page()
                    page.goto(f"chrome-extension://{extension_id}/settings.html")
                    expect(page.locator("#settings-save-state")).to_have_text("Settings saved", timeout=15000)
                    page.locator("#backend-url").fill(address)
                    page.locator("#backend-pairing-code").fill(code)
                    page.locator("#pair-backend").click()
                    expect(page.locator("#backend-status")).to_contain_text("Paired with the backend", timeout=15000)
                    stored = worker.evaluate("() => chrome.storage.local.get('backendToken').then(r => r.backendToken)")
                    with open(os.path.join(data_dir, "veilux_backend.key"), encoding="utf-8") as handle:
                        check("pairing stores the backend's key in the extension", stored == handle.read().strip())
                    page.locator("#check-backend").click()
                    expect(page.locator("#backend-status")).to_contain_text("this browser is paired with it", timeout=15000)
                    check("Check backend reports the browser as paired", True)
                    # As after "Save settings": the extension now uses this address for every request.
                    worker.evaluate("address => chrome.storage.local.set({backendUrl: address})", address)
                    result = page.evaluate("""async () => {
                      const response = await VeiluxBackend.fetch('/sanitize', {method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({logs: ['{"user":"j.doe","src_ip":"10.20.30.40"}']})});
                      return {status: response.status, body: await response.json()};
                    }""")
                    text = result["body"].get("sanitized_log", "")
                    check("signed requests from the extension are answered",
                          result["status"] == 200 and "10.20.30.40" not in text and "⟦" in text, str(result)[:300])
                    unsigned = page.evaluate(f"""() => fetch('{address}/sanitize', {{method: 'POST', headers: {{'Content-Type': 'application/json'}},
                      body: JSON.stringify({{logs: ['x']}})}}).then(r => r.status)""")
                    check("the same request without the key is refused", unsigned == 401, str(unsigned))
                finally:
                    browser.close()
        finally:
            check("the backend stops cleanly", backend.interrupt() == 0, backend.output)
    print("Pairing end to end: all checks passed.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
