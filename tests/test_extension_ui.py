"""Real Chromium DOM tests with mocked extension APIs and external HTTP.
Run: python -m unittest discover -s tests -p test_extension_ui.py -v
Requires: pip install playwright && python -m playwright install chromium
"""

import json
from contextlib import contextmanager
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
import unittest
import urllib.request
from playwright.sync_api import sync_playwright, expect
from secret_detection import MECHANISMS
from backend_key import TEST_BACKEND_KEY

ROOT = Path(__file__).resolve().parents[1]


class ExtensionUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "tests/ui_fixture.py"), str(cls.port)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.url + "/health", timeout=0.2)
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("Test server failed")
        cls.playwright = sync_playwright().start()
        # VEILUX_TEST_ENGINE=firefox or webkit runs the popup and Settings pages
        # in another browser engine (install it with `playwright install firefox`).
        cls.engine = os.environ.get('VEILUX_TEST_ENGINE', 'chromium')
        cls.browser = getattr(cls.playwright, cls.engine).launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.terminate()
        cls.server.wait(timeout=10)

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 760, "height": 1000})
        self.context.add_init_script(
            (ROOT / "tests/browser_mock.js").read_text(encoding="utf-8-sig")
        )
        self.page = self.context.new_page()
        self.errors = []
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.context.route(
            "http://localhost:8000/**",
            lambda route: route.continue_(
                url=route.request.url.replace("http://localhost:8000", self.url)
            ),
        )
        self.page.goto(self.url + "/extension/popup.html")
        expect(self.page.locator("#logs-textarea")).to_have_value(
            "password=synthetic-initial"
        )
        self.install_background()
        self.page.request.post(self.url + "/test/reset")

    def install_background(self):
        # The popup page starts its background worker itself (tests/browser_mock.js).
        if self.page.locator('#background-test').count():
            return
        self.page.evaluate(
            "() => {const f=document.createElement('iframe');f.id='background-test';f.hidden=true;document.body.appendChild(f);f.contentWindow.browser=window.browser;}"
        )
        self.page.frames[-1].evaluate(
            (ROOT / "extension/background.js").read_text(encoding="utf-8")
        )

    def tearDown(self):
        self.context.close()
        self.assertEqual([], self.errors)

    def select(self, selector, value):
        self.page.locator(selector).evaluate(
            '(el,v)=>{el.focus();const i=el.value.indexOf(v);el.setSelectionRange(i,i+v.length);el.dispatchEvent(new Event("select"));}',
            value,
        )

    def sanitize(self):
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator("#analyze-btn").click()
        # UUID/hash-shaped values in saved statistics need a review decision.
        # This helper accepts them when a test exercises an unrelated workflow.
        self.page.wait_for_timeout(300)
        if self.page.locator("#secret-review").is_visible():
            self.page.locator("#secret-review-list input").check()
            self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#status-text")).to_contain_text(
            "Sanitized!", timeout=15000
        )

    def test_default_prompt_runs_one_preflight_then_sanitizes(self):
        """A null default prompt used to differ from the loop's empty-string
        snapshot, causing an endless stream of /secrets/scan requests."""
        scans = []
        self.page.on(
            "request",
            lambda request: scans.append(request.url)
            if request.url.endswith("/secrets/scan") else None,
        )
        self.sanitize()
        self.assertEqual(1, len(scans), scans)
        expect(self.page.locator("#sanitized-textarea")).not_to_have_value("")

    def test_all_preferences_persist_and_notice_stays_visible(self):
        # The protection switches live in the Options stage.
        self.page.locator('#stage-tab-options').click()
        toggle = self.page.get_by_role('switch', name='Secret protection', exact=True)
        expect(toggle).to_be_checked()
        toggle.uncheck()
        self.page.locator('#sanitization-controls summary').click()
        self.page.locator("#enable-pattern").uncheck()
        self.page.locator("#enable-keywords").uncheck()
        self.page.locator("#enable-jsonkeys").uncheck()
        expect(self.page.locator("#secret-protection-notice")).to_be_visible()
        self.page.reload()
        expect(self.page.locator("#logs-textarea")).to_have_value(
            "password=synthetic-initial"
        )
        expect(self.page.get_by_role('switch', name='Secret protection', exact=True)).not_to_be_checked()
        preferences = self.page.evaluate("() => browser.storage.local.get('popupPreferences')")['popupPreferences']
        self.assertFalse(preferences['secretProtectionEnabled'])
        self.assertEqual({name: False for name in MECHANISMS}, preferences['secretProtection'])
        for key in ("pattern", "keywords", "jsonkeys"):
            expect(self.page.locator("#enable-" + key)).not_to_be_checked()
        self.install_background()
        self.sanitize()
        expect(self.page.locator("#sanitized-textarea")).to_have_value(
            "password=synthetic-initial"
        )
        self.assertEqual([], self.page.request.get(self.url + "/test/sent").json())

    def test_manual_selection_immediate_case_sensitive_undo_and_new_analysis(self):
        expect(self.page.locator("#hide-selection-btn")).to_be_disabled()
        self.page.locator("#logs-textarea").fill("same same SAME")
        self.page.locator('#analyst-data-toggle').click()
        self.page.locator("#analyst-data-textarea").fill("different same")
        self.select("#logs-textarea", "same")
        self.select("#analyst-data-textarea", "different")
        self.page.locator("#hide-selection-btn").click()
        self.assertNotIn(
            "different", self.page.locator("#sanitized-analyst-textarea").input_value()
        )
        self.assertIn(
            "same same SAME", self.page.locator("#sanitized-textarea").input_value()
        )
        self.page.locator("#undo-hide-btn").click()
        expect(self.page.locator("#analyst-data-textarea")).to_have_value(
            "different same"
        )
        self.select("#sanitized-textarea", "same")
        self.page.locator("#hide-selection-btn").click()
        value = self.page.locator("#sanitized-textarea").input_value()
        self.assertNotIn("same", value)
        self.assertIn("SAME", value)
        expect(self.page.locator("#manual-hide-status")).to_contain_text(
            "6 replacements"
        )
        self.sanitize()
        self.page.locator("#sanitized-textarea").fill(
            self.page.locator("#sanitized-textarea").input_value()
            + " edited same password=edited-secret"
        )
        self.page.locator('input[value="ai"]').check()
        self.page.locator('#ai-provider').select_option('groq')
        self.page.locator("#analyze-btn").click()
        self.page.wait_for_timeout(300)
        if self.page.locator("#secret-review").is_visible():
            self.page.locator("#secret-review-list input").check()
            self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#status-text")).to_contain_text(
            "Done!", timeout=15000
        )
        sent = self.page.request.get(self.url + "/test/sent").json()
        self.assertEqual(1, len(sent))
        self.assertNotIn("edited-secret", sent[0]["body"])
        self.assertNotIn("edited same", sent[0]["body"])
        prefs = self.page.evaluate("()=>browser.storage.local.get('popupPreferences')")
        self.assertNotIn("same", json.dumps(prefs))
        self.page.locator("#clear-btn").click()
        expect(self.page.locator("#undo-hide-btn")).to_be_disabled()
        self.page.locator("#logs-textarea").fill("same")
        self.sanitize()
        expect(self.page.locator("#sanitized-textarea")).to_have_value("same")

    def test_review_is_visible_keep_then_manual_hide_wins(self):
        self.page.locator("#logs-textarea").fill("authentication alice:review-value")
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator("#analyze-btn").click()
        expect(self.page.locator("#secret-review")).to_be_visible()
        expect(self.page.locator("#loading-overlay")).not_to_be_visible()
        expect(self.page.locator("#status-text")).to_have_text(
            "Waiting for your review"
        )
        self.page.locator("#secret-review-list input").check()
        self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#status-text")).to_contain_text("Sanitized!")
        self.select("#sanitized-textarea", "review-value")
        self.page.locator("#hide-selection-btn").click()
        self.page.locator("#sanitized-textarea").fill(
            self.page.locator("#sanitized-textarea").input_value()
            + " authentication bob:review-value"
        )
        self.page.locator('input[value="ai"]').check()
        self.page.locator('#ai-provider').select_option('groq')
        self.page.locator("#analyze-btn").click()
        self.page.wait_for_timeout(300)
        if self.page.locator("#secret-review").is_visible():
            self.page.locator("#secret-review-list input").check()
            self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#status-text")).to_contain_text(
            "Done!", timeout=15000
        )
        self.assertNotIn(
            "review-value", self.page.request.get(self.url + "/test/sent").text()
        )

    def test_scan_failure_shows_error_without_outbound_requests(self):
        self.page.route(
            "**/secrets/scan",
            lambda route: route.fulfill(
                status=500, json={"detail": "Synthetic scanner failure"}
            ),
        )
        self.page.locator("#analyze-btn").click()
        expect(self.page.locator("#status-text")).to_contain_text(
            "Secret scan could not complete"
        )
        expect(self.page.locator("#loading-overlay")).not_to_be_visible()
        self.assertEqual([], self.page.request.get(self.url + "/test/sent").json())

    def test_popup_page_never_scrolls_when_results_appear(self):
        # The toolbar popup is 600 px tall. Hidden helpers must not make the page
        # taller, or revealing results scrolls the header out of view.
        self.page.set_viewport_size({"width": 720, "height": 600})
        page_size = "() => [document.scrollingElement.scrollHeight, innerHeight, document.scrollingElement.scrollTop]"
        self.assertEqual([600, 600, 0], self.page.evaluate(page_size))
        self.page.locator("#logs-textarea").fill('{"event":"process created","user":"alice"}')
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator("#analyze-btn").click()
        expect(self.page.locator("#results-workspace")).to_be_visible(timeout=15000)
        expect(self.page.locator(".brand-name")).to_be_in_viewport(ratio=1)
        self.assertEqual([600, 600, 0], self.page.evaluate(page_size))

    def test_encoded_provider_is_never_keep_and_hash_requires_continuation(self):
        token = 'ghp_' + 'A' * 36
        hash_value = '0123456789abcdef' * 4
        self.page.locator('#logs-textarea').fill(
            '{"ref":"\\u0067' + token[1:] + '","hash":"' + hash_value + '"}')
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#secret-review')).to_be_visible()
        expect(self.page.locator('#secret-review-list')).not_to_contain_text(token)
        expect(self.page.locator('#secret-review-list')).to_contain_text(hash_value)
        expect(self.page.locator('#secret-review-list input')).to_be_checked()
        expect(self.page.locator('#status-text')).to_contain_text('Waiting for your review')
        self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())
        self.page.locator('#secret-review-list input').uncheck()
        self.page.locator('#secret-review-continue').click()
        expect(self.page.locator('#status-text')).to_contain_text('Sanitized!')
        value = self.page.locator('#sanitized-textarea').input_value()
        self.assertNotIn(token, value)
        self.assertNotIn(hash_value, value)
        self.assertIn('⟦SECRET#', value)

    def test_edits_and_checkbox_changes_during_review_are_rechecked(self):
        # An explicit custom review rule still applies when automatic methods
        # are off. Preserve the second-review/edit regression with the master UI.
        self.page.evaluate("() => browser.storage.local.set({customRegexRules: [{id:'edited-review', pattern:'second-value', action:'review', mode:'token', scope:'all', capture_group:0, enabled:true}]})")
        self.page.locator("#logs-textarea").fill("authentication alice:first-value")
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator("#analyze-btn").click()
        expect(self.page.locator("#secret-review")).to_be_visible()
        self.page.locator("#logs-textarea").fill(
            "authentication bob:second-value password=keep-by-choice"
        )
        # The protection switches live in the Options stage.
        self.page.locator('#stage-tab-options').click()
        self.page.get_by_role('switch', name='Secret protection', exact=True).uncheck()
        self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#secret-review-list")).to_contain_text("second-value")
        expect(self.page.locator("#secret-review-list input")).to_be_checked()
        self.page.locator("#secret-review-list input").uncheck()
        self.page.locator("#secret-review-continue").click()
        expect(self.page.locator("#status-text")).to_contain_text("Sanitized!")
        preview = self.page.locator("#sanitized-textarea").input_value()
        self.assertNotIn("second-value", preview)
        self.assertIn("password=keep-by-choice", preview)

    def test_secret_master_controls_scan_and_actual_model_payload(self):
        import base64
        token = 'ghp_' + 'A' * 36
        encoded = base64.b64encode(token.encode()).decode()
        originals = ['toggle-password-991', token, encoded]
        source = json.dumps({'password': originals[0], 'ref': token, 'encoded': encoded})
        self.page.locator('#logs-textarea').fill(source)
        self.page.locator('#sanitize-checkbox').uncheck()
        policies = []
        self.page.on('request', lambda request: policies.append((request.url.rsplit('/', 1)[-1], request.post_data_json))
                     if request.url.endswith(('/secrets/scan', '/analyze')) else None)

        def analyze(enabled):
            policies.clear()
            self.page.request.post(self.url + '/test/reset')
            # The protection switches live in the Options stage.
            self.page.locator('#stage-tab-options').click()
            toggle = self.page.get_by_role('switch', name='Secret protection', exact=True)
            toggle.set_checked(enabled)
            with self.page.expect_response(lambda response: response.url.endswith('/analyze')) as completed:
                self.page.locator('#analyze-btn').click()
            completed.value.finished()
            expect(self.page.locator('#status-text')).to_contain_text('Done!', timeout=15000)
            self.assertEqual(['scan', 'analyze'], [kind for kind, _ in policies])
            for _, payload in policies:
                self.assertEqual({name: enabled for name in MECHANISMS}, payload['secret_protection'])
            sent = self.page.request.get(self.url + '/test/sent').json()
            self.assertEqual(1, len(sent))
            prompt = json.loads(sent[0]['body'])['messages'][-1]['content']
            for original in originals:
                if enabled: self.assertNotIn(original, prompt)
                else: self.assertIn(original, prompt)
            if enabled: self.assertIn('⟦SECRET#', prompt)

        analyze(True)
        analyze(False)
        # Keyboard activation must re-enable every method, after saved Off.
        # The protection switches live in the Options stage.
        self.page.locator('#stage-tab-options').click()
        toggle = self.page.get_by_role('switch', name='Secret protection', exact=True)
        toggle.focus()
        toggle.press('Space')
        expect(toggle).to_be_checked()
        analyze(True)

    def test_secret_master_migrates_legacy_preferences_without_partial_state(self):
        legacy_names = [name for name in MECHANISMS if name not in ('heuristics', 'decoding')]
        cases = [
            ({'secretProtection': {name: False for name in legacy_names}}, False),
            ({'secretProtection': {'assignments': False, 'known_tokens': True}}, True),
            ({'secretProtection': {name: False for name in MECHANISMS}}, False),
            ({'secretProtection': {name: False for name in legacy_names} | {'decoding': True}}, True),
            ({'secretProtectionEnabled': False, 'secretProtection': {name: True for name in MECHANISMS}}, False),
        ]
        for preferences, enabled in cases:
            with self.subTest(preferences=preferences):
                self.page.evaluate('(prefs) => browser.storage.local.set({popupPreferences:prefs})', preferences)
                self.page.reload()
                expect(self.page.locator('#logs-textarea')).to_have_value('password=synthetic-initial')
                # The protection switches live in the Options stage.
                self.page.locator('#stage-tab-options').click()
                toggle = self.page.get_by_role('switch', name='Secret protection', exact=True)
                if enabled: expect(toggle).to_be_checked()
                else: expect(toggle).not_to_be_checked()
                self.assertEqual({name: enabled for name in MECHANISMS}, self.page.evaluate('collectSecretProtection()'))

    def test_manual_rule_survives_popup_reopen_without_permanent_preferences(self):
        self.page.locator("#logs-textarea").fill("ephemeral-secret")
        self.select("#logs-textarea", "ephemeral-secret")
        self.page.locator("#hide-selection-btn").click()
        self.page.reload()
        expect(self.page.locator("#undo-hide-btn")).to_be_enabled()
        self.install_background()
        self.page.locator("#logs-textarea").fill("ephemeral-secret")
        self.sanitize()
        self.assertNotIn(
            "ephemeral-secret", self.page.locator("#sanitized-textarea").input_value()
        )

    def test_slow_ti_progress_and_cancellation(self):
        self.page.locator("#logs-textarea").fill("8.8.8.8")
        self.page.locator("#enable-ti").check()
        self.page.locator("#analyze-btn").click()
        expect(self.page.locator("#loading-text")).to_contain_text(
            "Checking threat intelligence", timeout=10000
        )
        self.page.locator("#loading-dismiss-btn").click()
        expect(self.page.locator("#loading-overlay")).not_to_be_visible()
        self.page.wait_for_function(
            "async()=>!(await browser.storage.local.get('analysisInProgress')).analysisInProgress"
        )
        self.assertFalse(
            any(
                "groq.com" in x["url"]
                for x in self.page.request.get(self.url + "/test/sent").json()
            )
        )

    def page_review(self, values, html, *, fallback=False):
        """Use the real page DOM/ranges/controller; mock only extension transport
        and preflight findings so UI navigation tests never call a provider."""
        source_url = self.url + '/test/source'
        self.context.route('**/test/source', lambda route: route.fulfill(
            content_type='text/html', body='<meta charset="utf-8"><title>Captured security logs</title>' + html))
        with self.context.expect_page() as opened:
            self.page.evaluate('(url) => { window.reviewSourceWindow = window.open(url, "veilux-source-test"); }', source_url)
        source = opened.value
        source.wait_for_load_state()
        self.page.evaluate((ROOT / 'tests/page_review_bridge.js').read_text(encoding='utf-8'), {
            'script': (ROOT / 'extension/secret_highlights.js').read_text(encoding='utf-8'),
            'source': {'url': source_url}, 'fallback': fallback,
        })
        self.page.route('**/secrets/scan', lambda route: route.fulfill(json={
            'findings': [dict(value=value, reason='Synthetic review candidate', confidence='ambiguous', occurrence_count=284)
                         for value in values]}))
        self.page.locator('#logs-textarea').fill('\n'.join(values))
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#secret-review')).to_be_visible()
        return source

    def test_page_review_wraps_filters_and_jumps_without_changing_keep(self):
        value = 'customer-0123456789-<tag>-雪-' * 12
        values = [value] + [f'candidate-{i:04d}' for i in range(100)]
        import html
        source = self.page_review(values,
            '<div style="height:1600px">Header</div><pre id="logs">' + html.escape(value) +
            '\n' + ('padding\n' * 150) + html.escape(value) + '</pre>')
        original = source.locator('body').inner_text()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('2 page matches highlighted')
        button = self.page.locator('[data-find-secret="0"]')
        self.assertEqual(value, button.inner_text())
        self.assertTrue(button.evaluate('(el) => el.scrollWidth <= el.clientWidth'))
        self.assertGreater(button.bounding_box()['height'], 30)
        button.click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
        y1 = source.evaluate('scrollY')
        self.assertGreater(y1, 1000)
        button.press('Enter')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 2 of 2')
        self.assertGreater(source.evaluate('scrollY'), y1 + 500)
        self.page.locator('[data-previous-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
        expect(self.page.locator('[data-secret-index="0"]')).to_be_checked()
        self.page.locator('#secret-review-filter').fill('candidate-0099')
        expect(self.page.locator('#secret-review-count')).to_have_text('1 of 101 values')
        self.page.locator('[data-secret-index="100"]').uncheck()
        self.page.locator('#secret-review-filter').fill('')
        expect(self.page.locator('[data-secret-index="100"]')).not_to_be_checked()
        self.assertEqual(original, source.locator('body').inner_text())
        self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())
        self.page.locator('#secret-review-cancel').click()
        source.wait_for_function('CSS.highlights.size === 0')

    def test_page_review_rejects_other_tabs_and_changed_pages(self):
        source = self.page_review(['visible-candidate'], '<p>visible-candidate</p>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('1 page matches highlighted')
        self.page.evaluate("() => { reviewDispatches.length = 0; reviewActiveTab = { id: 72, url: 'https://unrelated.test/', active: true }; }")
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('Switch to “Captured security logs”')
        self.assertEqual([], self.page.evaluate('reviewDispatches'))
        source.wait_for_function('CSS.highlights.size === 0')
        self.page.evaluate('() => { reviewActiveTab = reviewTab; }')
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        self.page.evaluate("() => { reviewDispatches.length = 0; reviewTab.url += '#different-document'; }")
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('navigated to another page')
        self.assertEqual([], self.page.evaluate('reviewDispatches'))

    def test_page_review_handles_inline_text_frames_shadow_and_live_changes(self):
        source = self.page_review(['split-value', 'frame-value', 'shadow-value', 'absent-value'],
            '<p>split-<b>value</b></p><div id="shadow"></div><p hidden>absent-value</p>'
            '<script>/* absent-value */</script><iframe srcdoc="<p>frame-value</p>"></iframe>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('2 page matches highlighted')
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        self.assertEqual(['split-value'], source.evaluate(
            'Array.from(CSS.highlights.values()).flatMap(h => Array.from(h, r => r.toString())).filter(v => v === "split-value").slice(0,1)'))
        self.page.locator('[data-find-secret="1"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        source.evaluate('() => { document.getElementById("shadow").attachShadow({mode:"open"}).innerHTML="<p>shadow-value</p>"; }')
        self.page.locator('[data-find-secret="2"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        self.page.locator('[data-find-secret="3"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('not currently displayed')
        source.locator('body').evaluate('(el) => { const p=document.createElement("p");p.textContent="absent-value";el.appendChild(p); }')
        self.page.locator('#secret-review-refresh').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('4 page matches highlighted')
        self.page.locator('#secret-review-cancel').click()
        source.wait_for_function('CSS.highlights.size === 0')
        self.assertEqual(0, source.frames[1].evaluate('CSS.highlights.size'))
        self.assertEqual(0, source.evaluate('document.getElementById("shadow").shadowRoot.querySelectorAll("style").length'))

    def test_page_review_overlay_fallback_and_popup_close_cleanup(self):
        source = self.page_review(['fallback-candidate'], '<p>fallback-candidate</p>', fallback=True)
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('1 page matches highlighted')
        self.assertEqual(1, source.locator('canvas').count())
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        self.assertEqual('fallback-candidate', source.locator('body').inner_text())
        # Closing the popup leaves the highlights, so the values can be checked
        # on the page; Esc on the page removes them.
        self.page.goto(self.url + '/health')
        self.page.wait_for_timeout(500)
        expect(source.locator('canvas')).to_have_count(1)
        source.keyboard.press('Escape')
        expect(source.locator('canvas')).to_have_count(0)

    def test_page_review_falls_back_when_style_sheets_cannot_be_extended(self):
        """Firefox shows a content script the page's adoptedStyleSheets through a
        security wrapper that is not iterable. Highlighting must still work."""
        self.context.add_init_script("""Object.defineProperty(Document.prototype, 'adoptedStyleSheets', {
            configurable: true, get() { return { length: 0 }; }, set(value) { throw new TypeError('root.adoptedStyleSheets is not iterable'); } });""")
        source = self.page_review(['wrapped-candidate'], '<p>wrapped-candidate</p>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('1 page matches highlighted')
        expect(source.locator('canvas')).to_have_count(1)
        self.assertEqual(0, source.evaluate('CSS.highlights.size'))
        self.page.locator('[data-find-secret="0"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('match 1 of 1')
        self.assertEqual('wrapped-candidate', source.locator('body').inner_text())
        self.page.locator('#secret-review-cancel').click()
        expect(source.locator('canvas')).to_have_count(0)

    def test_page_review_source_persists_and_continue_removes_highlights(self):
        source = self.page_review(['persisted-candidate'], '<p>persisted-candidate</p>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('1 page matches highlighted')
        stored = self.page.evaluate("() => browser.storage.local.get(['capturedLogPages', 'capturedLogs'])")
        self.assertEqual(71, stored['capturedLogPages'][0]['id'])
        self.assertEqual('persisted-candidate', stored['capturedLogs'][0])
        self.page.locator('[data-secret-index="0"]').uncheck()
        self.page.locator('#secret-review-continue').click()
        expect(self.page.locator('#status-text')).to_contain_text('Sanitized!')
        expect(self.page.locator('#sanitized-textarea')).not_to_have_value('persisted-candidate')
        source.wait_for_function('CSS.highlights.size === 0')

    def test_page_review_overlap_case_display_limits_and_refresh(self):
        source = self.page_review(['abc', 'bc', 'abcabc', 'acrossblocks'],
            '<p id="text">abcabc ABC abc</p><div>across</div><div>blocks</div>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('7 page matches highlighted')
        self.page.locator('[data-find-secret="3"]').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('not currently displayed')
        source.locator('#text').evaluate('(el) => { el.textContent = "abc ".repeat(6000); }')
        self.page.locator('#secret-review-refresh').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('display limit')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('10000 page matches')
        self.assertEqual(1, source.evaluate('document.adoptedStyleSheets.length'))
        self.page.locator('#secret-review-cancel').click()
        source.wait_for_function('CSS.highlights.size === 0')
        self.assertEqual(0, source.evaluate('document.adoptedStyleSheets.length'))

    def test_page_review_source_survives_reopen_on_wrong_tab(self):
        source = self.page_review(['reopen-candidate'], '<p>reopen-candidate</p>')
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('1 page matches highlighted')
        self.page.locator('#secret-review-cancel').click()
        self.page.reload()
        expect(self.page.locator('#logs-textarea')).to_have_value('reopen-candidate')
        self.install_background()
        self.page.evaluate('() => { window.reviewSourceWindow = window.open("", "veilux-source-test"); }')
        self.page.evaluate((ROOT / 'tests/page_review_bridge.js').read_text(encoding='utf-8'), {
            'script': (ROOT / 'extension/secret_highlights.js').read_text(encoding='utf-8'),
            'source': {'url': source.url}, 'fallback': False,
        })
        self.page.evaluate("() => { reviewActiveTab = { id: 72, url: 'https://other.test/', active: true }; }")
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#secret-review-page-status')).to_contain_text('Switch to “Captured security logs”')
        self.assertEqual([], self.page.evaluate('reviewDispatches'))
        expect(self.page.locator('[data-secret-index="0"]')).to_be_checked()

    @contextmanager
    def native_extension(self, *extra_args):
        # Loading the real unpacked extension is a Chromium feature of Playwright;
        # Firefox is checked with web-ext (see docs/BROWSER_TESTING.md).
        if getattr(self, 'engine', 'chromium') != 'chromium':
            self.skipTest('Loading the real extension needs Chromium.')
        with tempfile.TemporaryDirectory(prefix='veilux-native-review-') as profile:
            native = None
            errors = []
            channels = [os.environ.get('VEILUX_EXTENSION_BROWSER', 'chromium')]
            if os.name == 'nt' and 'VEILUX_EXTENSION_BROWSER' not in os.environ:
                channels.append('msedge')
            for channel in channels:
                try:
                    native = self.playwright.chromium.launch_persistent_context(
                        profile, channel=channel, headless=True,
                        ignore_default_args=['--disable-extensions'],
                        args=[f'--disable-extensions-except={ROOT / "extension"}', f'--load-extension={ROOT / "extension"}', *extra_args])
                    break
                except Exception as error:
                    errors.append(str(error).split('Call log:')[0])
            if native is None:
                self.skipTest('Native extension browser unavailable: ' + '; '.join(errors))
            try:
                # The extension is paired with the test backend, as after Settings -> Backend -> Pair.
                worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=30000)
                worker.evaluate('key => chrome.storage.local.set({backendToken: key})', TEST_BACKEND_KEY)
                yield native
            finally:
                native.close()

    def test_native_toolbar_popup_opens_at_the_size_it_asks_for(self):
        """Open the real toolbar popup of the unpacked extension. It must come
        out at exactly 720x600 with the content filling it, and must not grow
        or shrink afterwards."""
        expression = """(() => { const c = document.querySelector('.container').getBoundingClientRect(),
            d = document.querySelector('.workflow-dock').getBoundingClientRect();
            return JSON.stringify({inner: [innerWidth, innerHeight], container: [Math.round(c.width), Math.round(c.height)],
              dock: [Math.round(d.right), Math.round(d.bottom)]}); })()"""
        for screen, expected in (('1920x1200', {'inner': [720, 600], 'container': [720, 600], 'dock': [704, 600]}), (None, None)):
            with self.subTest(screen=screen), self.native_extension(*(['--screen-info={' + screen + '}'] if screen else [])) as native:
                worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
                page = native.new_page()
                page.goto('about:blank')
                opened = worker.evaluate("() => chrome.action.openPopup().then(() => 'ok', error => error.message)")
                if opened != 'ok':
                    self.skipTest('This browser build cannot open the toolbar popup from a test: ' + opened)
                page.wait_for_timeout(1500)
                cdp = native.new_cdp_session(page)

                def measure():
                    target = next((t for t in cdp.send('Target.getTargets')['targetInfos'] if t.get('url', '').endswith('/popup.html')), None)
                    if not target:
                        self.skipTest('The toolbar popup is not reachable in this browser build.')
                    answers = []
                    listener = lambda event: answers.append(json.loads(event['message']))
                    cdp.on('Target.receivedMessageFromTarget', listener)
                    session = cdp.send('Target.attachToTarget', {'targetId': target['targetId'], 'flatten': False})['sessionId']
                    cdp.send('Target.sendMessageToTarget', {'sessionId': session, 'message': json.dumps(
                        {'id': 1, 'method': 'Runtime.evaluate', 'params': {'expression': expression, 'returnByValue': True}})})
                    for _ in range(50):
                        if answers:
                            break
                        page.wait_for_timeout(100)
                    cdp.remove_listener('Target.receivedMessageFromTarget', listener)
                    cdp.send('Target.detachFromTarget', {'sessionId': session})
                    return json.loads(answers[0]['result']['result']['value'])
                first = measure()
                page.wait_for_timeout(1000)
                self.assertEqual(first, measure(), 'the popup changed size after opening')
                if expected:
                    self.assertEqual(expected, first)
                else:
                    # A small screen: the browser opens a smaller popup, and the
                    # content still fills it with the action bar at the bottom edge.
                    self.assertEqual(first['inner'], first['container'])
                    self.assertEqual(first['inner'][1], first['dock'][1])

    def test_native_page_script_reader_runs_under_manifest_v3(self):
        """A connection's own page script must run in the real extension, where
        Manifest V3 forbids turning text into code inside extension scripts. It
        runs in the page instead, and a page that forbids eval gets a clear
        message."""
        script = ("const rows = Array.from(document.querySelectorAll('li')).map(li => ({event: li.textContent}));"
                  "await helpers.waitForElement('ul');"
                  "return {logs: rows, info: 'list items'};")
        with self.native_extension() as native:
            worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
            extension_id = worker.url.split('/')[2]
            body = '<meta charset="utf-8"><title>Script source</title><ul><li>first-scripted-event</li><li>second-scripted-event</li></ul>'
            native.route('**/test/script-source', lambda route: route.fulfill(content_type='text/html', body=body))
            native.route('**/test/strict-source', lambda route: route.fulfill(content_type='text/html', body=body,
                headers={'Content-Security-Policy': "script-src 'self'"}))
            for path, expected in (('/test/script-source', 'second-scripted-event'), ('/test/strict-source', "security policy does not allow page scripts")):
                with self.subTest(path=path):
                    source = native.new_page()
                    source.goto(self.url + path)
                    tab = worker.evaluate('(url) => chrome.tabs.query({}).then(tabs => tabs.find(tab => tab.url === url))', self.url + path)
                    worker.evaluate('(data) => chrome.storage.local.set(data)', {'capturedLogs': [], 'connectorProfiles': [{
                        'id': 'script-reader', 'name': 'Scripted SIEM', 'schemaVersion': 2, 'siemHost': '127.0.0.1', 'siemBaseUrl': self.url,
                        'discoverPathHint': path.split('/')[-1], 'dom': {'discover': {'strategy': 'custom_script', 'customScript': script}}}]})
                    with native.expect_page() as opened:
                        worker.evaluate('(url) => chrome.windows.create({url, type:"popup", width:780, height:800})',
                                        f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
                    popup = opened.value
                    popup.wait_for_load_state()
                    popup.locator('#extract-btn').click()
                    if 'strict' in path:
                        expect(popup.locator('#status-text')).to_contain_text(expected, timeout=10000)
                    else:
                        expect(popup.locator('#logs-textarea')).to_have_value(re.compile(expected), timeout=10000)
                        self.assertIn('first-scripted-event', popup.locator('#logs-textarea').input_value())
                    popup.close()
                    source.close()

    def test_native_extension_page_review_ports_and_tab_routing(self):
        """Load the actual unpacked extension: real isolated content scripts,
        tabs/windows, ports and CSP. Only preflight/provider HTTP is mocked."""
        with self.native_extension() as native:
            worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
            extension_id = worker.url.split('/')[2]
            native.route('http://localhost:8000/**', lambda route: route.continue_(
                url=route.request.url.replace('http://localhost:8000', self.url)))
            value = '54ec5ff9-8070-6ac3-cfaa-00000000a000'
            long_value = 'SourceHostName-' + 'synthetic-long-review-value-' * 7
            native.route('**/secrets/scan', lambda route: route.fulfill(json={'findings': [
                dict(value=candidate, reason='Synthetic review candidate', confidence='ambiguous', occurrence_count=2)
                for candidate in [value, long_value]]}))
            source_url = self.url + '/test/native-source'
            native.route('**/test/native-source', lambda route: route.fulfill(
                content_type='text/html', headers={'Content-Security-Policy': "default-src 'self'; style-src 'none'; script-src 'none'"},
                body='<meta charset="utf-8"><title>Captured security logs</title><h1>Security logs</h1>' +
                '<p>Earlier event</p>' * 90 + '<table><thead><tr><th>ref</th><th>message</th></tr></thead><tbody><tr><td>' +
                value + '</td><td>' + long_value + '</td></tr><tr><td>' + value + '</td><td>ordinary event</td></tr></tbody></table>'))
            source = native.new_page()
            source.goto(source_url)
            tab = worker.evaluate('(url) => chrome.tabs.query({}).then(tabs => tabs.find(tab => tab.url === url))', source_url)
            worker.evaluate('(data) => chrome.storage.local.set(data)', {
                'capturedLogs': [],
                'connectorProfiles': [{'id': 'native-review', 'name': 'Synthetic SIEM', 'schemaVersion': 2, 'siemHost': '127.0.0.1',
                    'siemBaseUrl': self.url, 'discoverPathHint': 'native-source', 'dom': {'discover': {'strategy': 'table_scrape'}}}],
                'groqApiKey': 'synthetic', 'providerModels': {'groq': {'id': 'llama-3.3-70b-versatile'}}, 'enablePatternSanitization': False,
            })
            with native.expect_page() as opened:
                worker.evaluate('(url) => chrome.windows.create({url, type:"popup", width:780, height:800})',
                    f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup = opened.value
            popup.wait_for_load_state()
            # The protection switches live in the Options stage.
            popup.locator('#stage-tab-options').click()
            master = popup.get_by_role('switch', name='Secret protection', exact=True)
            expect(master).to_be_checked()
            popup.locator('label[for="enable-secret-protection"]').click()
            expect(master).not_to_be_checked()
            popup.wait_for_function('async () => (await chrome.storage.local.get("popupPreferences")).popupPreferences?.secretProtectionEnabled === false')
            native_preferences = worker.evaluate('() => chrome.storage.local.get("popupPreferences")')
            self.assertEqual({name: False for name in MECHANISMS}, native_preferences['popupPreferences']['secretProtection'])
            popup.reload()
            expect(popup.get_by_role('switch', name='Secret protection', exact=True)).not_to_be_checked()
            popup.locator('label[for="enable-secret-protection"]').click()
            expect(popup.get_by_role('switch', name='Secret protection', exact=True)).to_be_checked()
            popup.locator('#extract-btn').click()
            expect(popup.locator('#status-text')).to_contain_text('Extracted 2 log(s)')
            self.assertIn(long_value, popup.locator('#logs-textarea').input_value())
            stored_pages = worker.evaluate('() => chrome.storage.local.get("capturedLogPages")')
            self.assertEqual([tab['id'], tab['id']], [page['id'] for page in stored_pages['capturedLogPages']])
            popup.locator('input[value="sanitize_only"]').check()
            popup.locator('#analyze-btn').click()
            expect(popup.locator('#secret-review-page-status')).to_contain_text('3 page matches highlighted')
            popup.locator('[data-find-secret="0"]').click()
            expect(popup.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
            self.assertGreater(source.evaluate('scrollY'), 1000)
            self.assertEqual(2, source.evaluate('CSS.highlights.size'))
            # Confirm the highlight stylesheet is installed even under the
            # page's style-src none policy, and no style nodes were added.
            self.assertEqual(1, source.evaluate('document.adoptedStyleSheets.length'))
            self.assertEqual(0, source.locator('style').count())
            screenshots = os.environ.get('VEILUX_REVIEW_SCREENSHOTS')
            if screenshots:
                destination = Path(screenshots)
                destination.mkdir(parents=True, exist_ok=True)
                popup.locator('#secret-review').screenshot(path=str(destination / 'credential-review.png'))
                source.screenshot(path=str(destination / 'page-highlights.png'))
            other = native.new_page()
            other.goto(self.url + '/health')
            other.bring_to_front()
            popup.bring_to_front()
            popup.locator('[data-find-secret="0"]').click()
            expect(popup.locator('#secret-review-page-status')).to_contain_text('Switch to “Captured security logs”')
            source.wait_for_function('CSS.highlights.size === 0')
            self.assertEqual(0, other.evaluate('CSS.highlights.size'))
            source.bring_to_front()
            popup.bring_to_front()
            popup.locator('[data-find-secret="0"]').click()
            expect(popup.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
            expect(popup.locator('[data-secret-index="0"]')).to_be_checked()
            popup.locator('#secret-review-continue').click()
            expect(popup.locator('#status-text')).to_contain_text('Sanitized!')
            source.wait_for_function('CSS.highlights.size === 0')
            # The same values were already decided for this case: no second review.
            popup.locator('#status-text').evaluate("node => node.textContent = ''")
            popup.locator('#analyze-btn').click()
            expect(popup.locator('#status-text')).to_contain_text('Sanitized!')
            expect(popup.locator('#secret-review')).to_be_hidden()
            self.assertEqual(0, source.evaluate('CSS.highlights.size'))
            popup.close()
            source.wait_for_function('CSS.highlights.size === 0')
            self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())

    def test_native_review_follows_linked_record_without_reextraction(self):
        # Exercise both fetch routes, actual link discovery on a case page and native
        # tab/window changes. A matching value on an unrelated SIEM document
        # must not authorize sending the candidate list to that document.
        for backend in [True, False]:
            with self.subTest(backend=backend), self.native_extension() as native:
                worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker')
                extension_id = worker.url.split('/')[2]
                value = '54ec5ff9-8070-6ac3-cfaa-00000000a000'
                log = json.dumps({'ref': value})
                siem_url = self.url + '/test/siem#/doc/events/one'
                case_url = self.url.replace('127.0.0.1', 'localhost') + '/test/case-page'
                native.route('http://localhost:8000/**', lambda route: route.continue_(
                    url=route.request.url.replace('http://localhost:8000', self.url)))
                native.route('**/secrets/scan', lambda route: route.fulfill(json={'findings': [
                    dict(value=value, reason='Synthetic review candidate', confidence='ambiguous', occurrence_count=2)]}))
                native.route('**/fetch-siem-logs', lambda route: route.fulfill(json={'logs': [log], 'failed': 0}))
                native.route('**/test/document/one', lambda route: route.fulfill(json={'hit': {'ref': value}}))
                native.route('**/test/case-page', lambda route: route.fulfill(content_type='text/html',
                    body=f'<title>Case page</title><div class="record-links"><a href="{siem_url}">Open SIEM event</a></div>'))
                native.route('**/test/siem', lambda route: route.fulfill(content_type='text/html',
                    body='<title>SIEM event</title>' + '<p>Earlier event</p>' * 90 + f'<pre>{value}\n{value}</pre>'))
                # Browser-session fetching needs an authenticated SIEM tab,
                # but that tab's unrelated starting page is not a log source.
                session = native.new_page()
                session.goto(self.url + '/health')
                case = native.new_page()
                case.goto(case_url)
                tab = worker.evaluate('(url) => chrome.tabs.query({}).then(tabs => tabs.find(t => t.url === url))', case_url)
                def focus_tab(target):
                    worker.evaluate('''async tab => {
                        await chrome.tabs.update(tab.id, {active:true});
                        await chrome.windows.update(tab.windowId, {focused:true});
                    }''', target)
                worker.evaluate('(data) => chrome.storage.local.set(data)', {
                    'capturedLogs': [], 'groqApiKey': 'synthetic', 'providerModels': {'groq': {'id': 'llama-3.3-70b-versatile'}}, 'enablePatternSanitization': False,
                    'connectorProfiles': [{'id': 'linked-review', 'name': 'Synthetic', 'schemaVersion': 2,
                        'websiteUrl': self.url, 'siemHost': '127.0.0.1', 'siemBaseUrl': self.url, 'verifySsl': False,
                        'maxRecords': 5000, 'statistics': {'mode': 'records'}, 'dom': {'discover': {'strategy': 'table_scrape'}},
                        'auth': {'type': 'header', 'headerName': 'Authorization', 'headerValue': 'synthetic'} if backend
                            else {'type': 'browser_session'},
                        'api': {'enabled': True, 'executeVia': 'backend' if backend else 'auto', 'fetchMode': 'single_request',
                            'linkRegex': r'/doc/(?<index>[^/]+)/(?<doc_id>[^/?#]+)', 'headersTemplate': {},
                            'method': 'POST', 'pathTemplate': '/test/document/${doc_id}',
                            'bodyTemplate': '{}', 'responsePath': 'hit'},
                        # Record links listed on another website's case page.
                        'pageSources': [{'name': 'Case page', 'website': 'localhost', 'urlIncludes': '', 'mode': 'links',
                            'selector': '.record-links a[href]', 'linkHost': '', 'rules': [],
                            'pattern': r'/doc/(?<index>[^/]+)/(?<doc_id>[^/?#]+)'}]}]})
                with native.expect_page() as opened:
                    worker.evaluate('(url) => chrome.windows.create({url, type:"popup", width:780, height:800})',
                        f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
                popup = opened.value
                popup.wait_for_load_state()
                popup.locator('#extract-btn').click()
                expect(popup.locator('#status-text')).to_contain_text('Extracted 1 log(s)')
                captured = worker.evaluate('() => chrome.storage.local.get("capturedLogPages")')
                self.assertIn(siem_url, captured['capturedLogPages'][0]['linkedUrls'])
                popup.locator('input[value="sanitize_only"]').check()
                popup.locator('#analyze-btn').click()
                expect(popup.locator('#secret-review')).to_be_visible()
                # Open the linked log after extraction/review. No SIEM Extract.
                siem = native.new_page()
                siem.goto(siem_url)
                siem_tab = worker.evaluate('(url) => chrome.tabs.query({}).then(tabs => tabs.find(t => t.url === url))', siem_url)
                siem.bring_to_front()
                popup.bring_to_front()
                popup.locator('[data-find-secret="0"]').click()
                expect(popup.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
                self.assertGreater(siem.evaluate('scrollY'), 1000)
                self.assertEqual(2, siem.evaluate('CSS.highlights.size'))
                saved = worker.evaluate('() => chrome.storage.local.get(["capturedLogPages", "capturedLogs"])')
                self.assertIn(siem_url, saved['capturedLogPages'][0]['linkedUrls'])
                expect(popup.locator('[data-secret-index="0"]')).to_be_checked()
                popup.evaluate('''() => {
                    window.highlightTargets = [];
                    const original = browser.scripting.executeScript;
                    browser.scripting.executeScript = options => {
                        if (options.files?.includes('secret_highlights.js')) highlightTargets.push(options.target.tabId);
                        return original(options);
                    };
                }''')
                # Same host, different document and identical candidate text.
                siem.goto(self.url + '/test/siem#/doc/events/unrelated')
                popup.bring_to_front()
                popup.locator('[data-find-secret="0"]').click()
                expect(popup.locator('#secret-review-page-status')).to_contain_text('Switch to')
                siem.wait_for_function('CSS.highlights.size === 0')
                self.assertEqual([], popup.evaluate('highlightTargets'))
                # Automatic highlighting on returning, without any jump click.
                siem.goto(siem_url)
                siem.bring_to_front()
                expect(popup.locator('#secret-review-page-status')).to_contain_text('2 page matches highlighted')
                siem.wait_for_function('CSS.highlights.size > 0')
                # A separate normal browser window is also a valid destination.
                with native.expect_page() as moved:
                    worker.evaluate('() => chrome.windows.create({url:"about:blank", type:"normal"})')
                second_window = moved.value
                # Attach Playwright routing before this window's first HTTP
                # request (chrome.windows.create can otherwise outrun it).
                second_window.goto(siem_url)
                self.assertIn(value, second_window.locator('body').inner_text())
                second_window.bring_to_front()
                second_window.wait_for_function('CSS.highlights.size > 0')
                siem.wait_for_function('CSS.highlights.size === 0')
                popup.bring_to_front()
                popup.locator('[data-find-secret="0"]').click()
                expect(popup.locator('#secret-review-page-status')).to_contain_text('match 1 of 2')
                self.assertGreater(second_window.evaluate('scrollY'), 1000)
                second_window.close()
                # Opening the link in the original case tab also changes the
                # document binding without treating the new URL as stale.
                case.goto(siem_url)
                focus_tab(tab)
                case.wait_for_function('CSS.highlights.size > 0', polling=100, timeout=5000)
                focus_tab(siem_tab)
                siem.wait_for_function('CSS.highlights.size > 0', polling=100, timeout=5000)
                case.wait_for_function('CSS.highlights.size === 0', polling=100, timeout=5000)
                popup.bring_to_front()
                popup.locator('[data-secret-index="0"]').uncheck()
                popup.locator('[data-find-secret="0"]').click()
                expect(popup.locator('[data-secret-index="0"]')).not_to_be_checked()
                # Persistence after popup closure; the original case tab can close.
                popup.close()
                # The highlights stay on the page after the popup closes.
                siem.wait_for_timeout(500)
                self.assertGreater(siem.evaluate('CSS.highlights.size'), 0)
                case.close()
                active = worker.evaluate('(url) => chrome.tabs.query({}).then(tabs => tabs.find(t => t.url === url))', siem_url)
                with native.expect_page() as reopened:
                    worker.evaluate('(url) => chrome.windows.create({url, type:"popup", width:780, height:800})',
                        f'chrome-extension://{extension_id}/popup.html?tabId={active["id"]}')
                popup = reopened.value
                popup.wait_for_load_state()
                # The interrupted review is offered back, with the choice already made.
                expect(popup.locator('#review-interrupted')).to_be_visible()
                expect(popup.locator('#review-interrupted-text')).to_contain_text('interrupted')
                popup.locator('#review-interrupted-resume').click()
                expect(popup.locator('#secret-review-page-status')).to_contain_text('2 page matches highlighted')
                expect(popup.locator('#review-interrupted')).to_be_hidden()
                expect(popup.locator('[data-secret-index="0"]')).not_to_be_checked()
                self.assertEqual(saved['capturedLogs'], worker.evaluate('() => chrome.storage.local.get("capturedLogs")')['capturedLogs'])
                popup.locator('#secret-review-cancel').click()
                siem.wait_for_function('CSS.highlights.size === 0')
                self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())


if __name__ == "__main__":
    unittest.main()
