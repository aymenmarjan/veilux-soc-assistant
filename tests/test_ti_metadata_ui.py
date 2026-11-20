"""Provider tables start closed, toggle independently and copy their full facts."""
import json
import unittest
from pathlib import Path
from playwright.sync_api import expect
import test_ui_redesign as harness


class ThreatIntelMetadataUITests(unittest.TestCase):
    setUpClass = classmethod(harness.InterfaceUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.InterfaceUITests.tearDownClass.__func__)
    setUp = harness.InterfaceUITests.setUp
    tearDown = harness.InterfaceUITests.tearDown
    install_background = harness.InterfaceUITests.install_background
    store = harness.InterfaceUITests.store
    clipboard = harness.InterfaceUITests.clipboard

    def test_isp_visible_when_expanded_and_copied_while_collapsed(self):
        self.store({'capturedLogs': [json.dumps({'dst_ip': ip}) for ip in ('192.0.2.138', '198.51.100.212')],
                    'virustotalApiKey': 'synthetic', 'abuseipdbApiKey': 'synthetic',
                    'enablePatternSanitization': True, 'popupPreferences': {'tiWhois': False}})
        self.page.reload()
        self.install_background()
        self.page.locator('input[value="ai"]').check()
        self.page.locator('#ai-provider').select_option('groq')
        self.page.locator('#sanitize-checkbox').check()
        self.page.locator('#enable-ti').check()
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
        self.page.locator('#tab-ti').click()
        feed = self.page.locator('#threat-intel-findings')
        expect(feed.locator('.ti-finding')).to_have_count(2)
        expect(feed.locator('.ti-provider')).to_have_count(4)
        expect(feed.locator('details[open]')).to_have_count(0)
        expect(feed).not_to_contain_text('⟦SECRET#')
        for table in feed.locator('dl').all():
            expect(table).to_be_hidden()
        fibre = feed.locator('.ti-finding').filter(has_text='198.51.100.212').locator('.ti-provider').filter(
            has=self.page.locator('summary', has_text='AbuseIPDB'))
        fibre.locator('summary').click()
        expect(fibre.locator('dl')).to_be_visible()
        expect(fibre).to_contain_text('EXAMPLE-FIBRE-QXRVLT02')
        expect(feed.locator('details[open]')).to_have_count(1)
        fibre.locator('summary').focus()
        self.page.keyboard.press('Enter')
        expect(fibre.locator('dl')).to_be_hidden()
        self.page.keyboard.press('Space')
        expect(fibre.locator('dl')).to_be_visible()
        fibre.locator('summary').click()
        self.clipboard()
        for button in ('#copy-result-action', '#copy-ti-btn'):
            self.page.locator(button).click()
            copied = self.page.evaluate('window.copied')
            self.assertIn('EXAMPLE-FIBRE-QXRVLT02', copied)
            self.assertIn('Example Fibre Ltd.', copied)
            self.assertIn('92', copied)
            self.assertIn('0%', copied)
            expect(feed.locator('details[open]')).to_have_count(0)
            expect(self.page.locator('.ti-finding')).to_have_count(2)
            expect(self.page.locator(button)).to_be_focused()
        sent = self.page.request.get(self.url + '/test/sent').json()
        self.assertEqual(4, sum('groq.com' not in r['url'] for r in sent))
        ai = next(r for r in sent if 'groq.com' in r['url'])
        self.assertNotIn('198.51.100.212', ai['body'])
        fibre.locator('summary').click()
        self.page.reload()
        self.page.locator('#tab-ti').click()
        expect(feed.locator('details[open]')).to_have_count(0)
        expect(feed).to_contain_text('EXAMPLE-FIBRE-QXRVLT02')
        self.page.evaluate("document.documentElement.classList.add('standalone-popup')")
        self.page.set_viewport_size({'width': 720, 'height': 1000})
        destination = Path(__file__).resolve().parents[2].parent / 'outputs' / 'ti-metadata-collapsed.png'
        feed.screenshot(path=str(destination))
        fibre.locator('summary').click()
        fibre.screenshot(path=str(destination.with_name('ti-metadata-isp.png')))
