"""Real preflight, popup, background and backend; external HTTP is synthetic."""
import json
import unittest
from pathlib import Path
from playwright.sync_api import expect
import test_ui_redesign as harness
from test_ti_hash_review import MD5, SHA256, IMPHASH


class ThreatIntelHashUITests(unittest.TestCase):
    setUpClass = classmethod(harness.InterfaceUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.InterfaceUITests.tearDownClass.__func__)
    setUp = harness.InterfaceUITests.setUp
    tearDown = harness.InterfaceUITests.tearDown
    install_background = harness.InterfaceUITests.install_background
    store = harness.InterfaceUITests.store
    clipboard = harness.InterfaceUITests.clipboard

    def analyze_hashes(self, hide_md5=False):
        hashes = f'MD5={MD5},SHA256={SHA256},IMPHASH={IMPHASH}'
        self.store({'capturedLogs': [json.dumps({'Hashes': hashes, 'message': 'Hashes: ' + hashes,
                                               'event_ip': '10.48.17.93'})],
                    'virustotalApiKey': 'synthetic', 'abuseipdbApiKey': '', 'enablePatternSanitization': True})
        self.page.reload()
        self.install_background()
        self.page.locator('input[value="ai"]').check()
        self.page.locator('#ai-provider').select_option('groq')
        self.page.locator('#sanitize-checkbox').check()
        self.page.locator('#enable-ti').check()
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#secret-review')).to_be_visible()
        candidates = self.page.locator('#secret-review-list input[data-secret-index]')
        expect(candidates).to_have_count(3)
        for candidate in candidates.all():
            expect(candidate).to_be_checked()
        if hide_md5:
            self.page.locator('.secret-review-item').filter(has_text=MD5).locator('input').uncheck()
        self.page.locator('#secret-review-continue').click()
        expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
        self.page.locator('#tab-ti').click()
        return self.page.request.get(self.url + '/test/sent').json()

    def test_kept_hash_feed_links_copy_and_persistence(self):
        sent = self.analyze_hashes()
        lookups = [r for r in sent if 'virustotal.com' in r['url']]
        self.assertEqual({MD5.lower(), SHA256.lower()}, {r['url'].rsplit('/', 1)[1] for r in lookups})
        self.assertEqual(2, len(lookups))
        card = self.page.locator('#threat-intel-findings')
        expect(card).not_to_contain_text('⟦SECRET#')
        expect(card).to_contain_text('secedit.exe')
        expect(card).to_contain_text('40960 bytes')
        expect(card).to_contain_text('IMPHASH')
        expect(card).to_contain_text('VirusTotal — not queried')
        expect(card).not_to_contain_text('Network owner')
        expect(card.locator('a')).to_have_count(2)
        links = card.locator('a').evaluate_all('(links)=>links.map(link=>link.href)')
        self.assertEqual({MD5.lower(), SHA256.lower()}, {link.rsplit('/', 1)[1] for link in links})
        self.clipboard()
        self.page.locator('#copy-result-action').click()
        self.assertIn(SHA256.lower(), self.page.evaluate('window.copied'))
        self.page.reload()
        self.page.locator('#tab-ti').click()
        expect(card).to_contain_text(MD5.lower())
        expect(card.locator('a')).to_have_count(2)
        self.page.set_viewport_size({'width': 720, 'height': 600})
        self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth <= innerWidth'))
        destination = Path(__file__).resolve().parents[2].parent / 'outputs' / 'ti-hash-popup.png'
        self.page.screenshot(path=str(destination))
        self.page.evaluate("document.documentElement.classList.add('standalone-popup')")
        self.page.set_viewport_size({'width': 720, 'height': 1100})
        card.locator('.ti-finding').first.locator('summary').click()
        card.locator('.ti-finding').first.screenshot(path=str(destination.with_name('ti-hash-cards.png')))

    def test_unchecked_hash_never_reaches_provider(self):
        sent = self.analyze_hashes(hide_md5=True)
        lookups = [r for r in sent if 'virustotal.com' in r['url']]
        self.assertEqual([SHA256.lower()], [r['url'].rsplit('/', 1)[1] for r in lookups])
        card = self.page.locator('#threat-intel-findings')
        expect(card).not_to_contain_text(MD5.lower())
        expect(card).to_contain_text(SHA256.lower())
        ai = next(r for r in sent if 'groq.com' in r['url'])
        self.assertNotIn(MD5.lower(), ai['body'].lower())
