"""Actual popup/background/backend flow with only external HTTP mocked."""
import json
import unittest
from playwright.sync_api import expect
import test_ui_redesign as harness

IP = '203.0.113.146'


class ThreatIntelPrivacyUITests(unittest.TestCase):
    setUpClass = classmethod(harness.InterfaceUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.InterfaceUITests.tearDownClass.__func__)
    setUp = harness.InterfaceUITests.setUp
    tearDown = harness.InterfaceUITests.tearDown
    install_background = harness.InterfaceUITests.install_background
    store = harness.InterfaceUITests.store
    stored = harness.InterfaceUITests.stored
    clipboard = harness.InterfaceUITests.clipboard

    def prepare(self, extra=None):
        self.store({'capturedLogs': ['ip=' + IP], 'enablePatternSanitization': True,
                    'abuseipdbApiKey': 'synthetic', 'virustotalApiKey': '', **(extra or {})})
        self.page.reload()
        self.install_background()
        self.page.locator('input[value="ai"]').check()
        self.page.locator('#ai-provider').select_option('groq')
        self.page.locator('#sanitize-checkbox').check()
        self.page.locator('#enable-ti').check()

    def analyze(self):
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
        self.page.locator('#tab-ti').click()

    def test_public_statistics_and_logs_enrich_while_ai_stays_masked(self):
        stats = [{'indexPattern': 'events-*', 'sampled': 2, 'total': 2, 'fields': [
            {'field': 'destination.ip', 'count': 2, 'percentage': 100,
             'topValues': [{'value': IP, 'count': 2, 'percentage': 100}]}]}]
        self.prepare({'fieldStatistics': stats})
        self.clipboard()
        self.analyze()
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('Synthetic ISP')
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('54')
        requests = self.page.request.get(self.url + '/test/sent').json()
        self.assertEqual(1, sum('api.abuseipdb.com' in r['url'] for r in requests))
        provider = next(r for r in requests if 'api.abuseipdb.com' in r['url'])
        self.assertIn(IP, provider['url'])
        ai = next(r for r in requests if 'groq.com' in r['url'])
        self.assertNotIn(IP, ai['body'])
        self.assertIn('IP_EXT#', ai['body'])
        self.page.locator('#copy-result-action').click()
        self.assertIn('Synthetic ISP', self.page.evaluate('window.copied'))
        self.page.locator('#tab-changes').click()
        self.page.locator('#mapping-toggle').click()
        expect(self.page.locator('#mapping-table')).to_contain_text(IP)
        self.page.reload()
        self.page.locator('#tab-ti').click()
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('Synthetic ISP')
        self.page.locator('#clear-btn').click()
        self.assertIsNone(self.stored('lastThreatIntelStatus'))
        expect(self.page.locator('#results-workspace')).to_be_hidden()

    def test_internal_only_explains_no_lookups_and_copies_status(self):
        self.prepare({'capturedLogs': ['ip=192.168.1.18']})
        self.clipboard()
        self.analyze()
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('Private/internal')
        requests = self.page.request.get(self.url + '/test/sent').json()
        self.assertTrue(all('groq.com' in r['url'] for r in requests))
        self.page.locator('#copy-result-action').click()
        self.assertIn('Private/internal', self.page.evaluate('window.copied'))
        self.page.reload()
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('Private/internal')

    def test_internal_configuration_stays_active_with_privacy_off(self):
        self.prepare({'customCidrsList': [{'cidr': '203.0.113.0/24', 'enabled': True}],
                      'customDomainsList': [{'domain': 'example.net', 'enabled': True}],
                      'capturedLogs': ['ip=' + IP + ' host=mail.example.net']})
        self.page.locator('#sanitize-checkbox').uncheck()
        self.analyze()
        requests = self.page.request.get(self.url + '/test/sent').json()
        self.assertTrue(all('groq.com' in r['url'] for r in requests), json.dumps(requests))
        expect(self.page.locator('#threat-intel-findings')).to_contain_text('Private/internal')
