"""Browser controls and structured TI cards; all provider requests mocked."""
import unittest
from pathlib import Path
from playwright.sync_api import expect
import test_ui_redesign as harness


class ThreatIntelUITests(unittest.TestCase):
    setUpClass=classmethod(harness.InterfaceUITests.setUpClass.__func__)
    tearDownClass=classmethod(harness.InterfaceUITests.tearDownClass.__func__)
    setUp=harness.InterfaceUITests.setUp
    tearDown=harness.InterfaceUITests.tearDown
    install_background=harness.InterfaceUITests.install_background
    store=harness.InterfaceUITests.store
    settings=harness.InterfaceUITests.settings
    mock_json=harness.InterfaceUITests.mock_json

    def tools(self):
        self.page.locator('#stage-tab-tools').click()
        self.page.locator('#ioc-lookup-toggle').click()

    def test_keyless_manual_whois_and_source_switches(self):
        self.store({'virustotalApiKey':'','abuseipdbApiKey':''})
        calls=self.mock_json('threat-intel/lookup',{'ioc':'mail.example.co.uk','type':'domain','verdict':'unknown','lookup_status':'complete',
            'sources':{'whois':{'status':'ok','requested_domain':'mail.example.co.uk','queried_domain':'example.co.uk','registrar':'Synthetic registrar','age_days':500}}})
        self.tools()
        self.page.locator('#manual-ti-vt').uncheck()
        self.page.locator('#manual-ti-abuse').uncheck()
        self.page.locator('#ioc-lookup-input').fill('mail.example.co.uk')
        self.page.locator('#ioc-lookup-btn').click()
        expect(self.page.locator('#ioc-lookup-result')).to_contain_text('Synthetic registrar')
        expect(self.page.locator('#ioc-lookup-result')).to_contain_text('Registration lookup for')
        self.assertFalse(calls[0]['enable_virustotal'])
        self.assertFalse(calls[0]['enable_abuseipdb'])
        self.assertTrue(calls[0]['enable_whois'])
        self.assertFalse(calls[0]['use_cache'])
        self.assertIsNone(calls[0]['abuseipdb_api_key'])
        self.page.locator('#manual-ti-whois').uncheck()
        self.page.locator('#ioc-lookup-btn').click()
        expect(self.page.locator('#ioc-lookup-result')).to_contain_text('Enable WHOIS')
        self.assertEqual(1,len(calls))
        self.page.reload()
        self.tools()
        expect(self.page.locator('#manual-ti-vt')).not_to_be_checked()
        expect(self.page.locator('#manual-ti-whois')).not_to_be_checked()
        self.page.locator('#manual-ti-whois').check()
        expect(self.page.locator('#enable-ti-whois')).to_be_checked()

    def test_structured_abuse_card_zero_counts_and_no_invented_city(self):
        self.store({'abuseipdbApiKey':'synthetic'})
        self.mock_json('threat-intel/lookup',{'ioc':'203.0.113.146','type':'ip','verdict':'clean','lookup_status':'complete',
            'sources':{'abuseipdb':{'status':'ok','abuse_confidence_score':0,'total_reports':54,'report_window_days':90,
                'isp':'Example Transit Networks','usage_type':'Fixed Line ISP','domain':'example.net','country':'PT','country_name':'Portugal',
                'distinct_reporters':12,'is_tor':False,'ip_version':4,'is_public':True,'is_whitelisted':False,'hostnames':[],
                'checked_at':'2026-10-12T12:00:00Z','last_reported_at':'2026-10-01T12:00:00Z',
                'link':'https://www.abuseipdb.com/check/203.0.113.146'}}})
        self.tools()
        self.page.locator('#manual-ti-vt').uncheck()
        self.page.locator('#manual-ti-whois').uncheck()
        self.page.locator('#ioc-lookup-input').fill('203.0.113.146')
        self.page.locator('#ioc-lookup-btn').click()
        card=self.page.locator('#ioc-lookup-result')
        expect(card.locator('details[open]')).to_have_count(0)
        expect(card.locator('dl')).to_be_hidden()
        card.locator('summary').click()
        expect(card.locator('dl')).to_be_visible()
        expect(card).to_contain_text('Example Transit Networks')
        for label,value in [('Abuse confidence','0%'),('Reports in the last 90 days','54'),('Usage type','Fixed Line ISP'),
                            ('Domain name','example.net'),('Country','Portugal'),('Tor exit node','No')]:
            expect(card.locator('dt',has_text=label).locator('xpath=following-sibling::dd[1]')).to_contain_text(value)
        expect(card).to_contain_text('Not provided by the AbuseIPDB check API')
        expect(card.locator('a')).to_have_attribute('rel','noopener noreferrer')
        card.locator('summary').click()
        expect(card.locator('dl')).to_be_hidden()
        card.locator('summary').click()
        expect(card.locator('dl')).to_be_visible()
        for width in (720,360):
            self.page.evaluate("document.documentElement.classList.add('standalone-popup')")
            self.page.set_viewport_size({'width':width,'height':900})
            self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth <= innerWidth'))
        self.page.set_viewport_size({'width':720,'height':1000})
        destination=Path(__file__).resolve().parents[2].parent/'outputs'/'threat-intel-preview.png'
        destination.parent.mkdir(exist_ok=True)
        card.screenshot(path=str(destination))

    def test_enrichment_cards_escape_provider_values_and_show_partial_results(self):
        result={'ioc':'example.net','type':'domain','verdict':'unknown','lookup_status':'partial','sources':{
            'virustotal':{'status':'ok','asn':64500,'as_owner':'<img src=x onerror=alert(1)>','country':'PT'},
            'whois':{'status':'timeout','detail':'Synthetic timeout'}}}
        self.page.evaluate('(finding)=>displayThreatIntelFindings([finding])',result)
        self.page.evaluate("document.querySelector('#results-workspace').hidden=false")
        self.page.locator('#tab-ti').click()
        card=self.page.locator('#threat-intel-findings')
        expect(card).to_contain_text('AS64500')
        expect(card).to_contain_text('<img src=x onerror=alert(1)>')
        expect(card.locator('img')).to_have_count(0)
        expect(card).to_contain_text('Synthetic timeout')
        expect(card).to_contain_text('Some sources are unavailable')
        expect(card).to_contain_text('Not available')

    def test_key_test_uses_fresh_provider_checks_and_reports_rejection(self):
        self.settings()
        self.page.locator('#virustotal-api-key').fill('synthetic')
        self.page.locator('#abuseipdb-api-key').fill('synthetic')
        calls=self.mock_json('threat-intel/lookup',{'verdict':'unknown','sources':{
            'virustotal':{'status':'error','detail':'HTTP 401'},'abuseipdb':{'status':'rate_limited'}}})
        self.page.locator('#test-threat-intel-btn').click()
        expect(self.page.locator('#threat-intel-test-result')).to_contain_text('some keys could not be verified')
        expect(self.page.locator('#threat-intel-test-result')).to_contain_text('HTTP 401')
        self.assertFalse(calls[0]['use_cache'])
        self.assertFalse(calls[0]['enable_whois'])
        self.assertTrue(calls[0]['enable_virustotal'] and calls[0]['enable_abuseipdb'])
        expect(self.page.locator('#test-threat-intel-btn')).to_be_enabled()
