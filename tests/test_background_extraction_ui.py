"""Extraction and statistics run in the background worker and survive the popup closing."""
import json
import re
import time
import unittest
from playwright.sync_api import expect
import test_connector_setup_ui as setup
import test_extension_ui as harness


def api_profile(name='Slow API', host='console.test', path='/slow-records'):
    return dict(id=name, name=name, schemaVersion=2, websiteUrl='https://' + host, siemHost=host,
        siemBaseUrl='https://records.test', auth={'type': 'none'}, maxRecords=5000,
        dom={'discover': {'strategy': 'api_request'}}, statistics={'mode': 'records'}, pageSources=[],
        api={'enabled': True, 'method': 'GET', 'pathTemplate': path, 'responsePath': 'data.records'})


class BackgroundExtractionTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background
    native_extension = harness.ExtensionUITests.native_extension
    tab = setup.ConnectorSetupTests.tab

    def popup(self, profiles, **storage):
        self.page.evaluate('data => browser.storage.local.set(data)', {'connectorProfiles': profiles, **storage})
        self.page.goto(self.url + '/extension/popup.html')
        self.tab('https://console.test/events')

    def stored(self, key):
        return self.page.evaluate('(key) => browser.storage.local.get(key)', key).get(key)

    def test_statistics_use_the_chosen_sample_size(self):
        self.popup([api_profile(path='/records')])
        sample = self.page.locator('#statistics-sample-size')
        expect(sample).to_have_value('5000')
        sample.fill('1')
        sample.dispatch_event('change')
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('alice', timeout=10000)
        self.assertEqual(1, self.stored('fieldStatistics')[0]['sampled'])
        self.assertTrue(self.stored('fieldStatistics')[0]['limited'])
        sent = [r['url'] for r in self.page.request.get(self.url + '/test/sent').json() if 'records.test' in r['url']]
        self.assertEqual(['https://records.test/records'], sent)
        self.page.reload()
        expect(self.page.locator('#statistics-sample-size')).to_have_value('1')

    def test_captured_logs_statistics_respect_the_sample_size(self):
        logs = [json.dumps({'user': name}) for name in ('alice', 'bob', 'carol')]
        profile = api_profile(path='/records'); profile['statistics'] = {'mode': 'captured'}
        self.popup([profile], capturedLogs=logs, popupPreferences={'statisticsSampleSize': 2})
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('alice', timeout=10000)
        stat = self.stored('fieldStatistics')[0]
        self.assertEqual((2, True), (stat['sampled'], stat['limited']))
        self.assertEqual([], self.page.request.get(self.url + '/test/sent').json())

    def test_statistics_keep_the_chosen_number_of_top_values(self):
        logs = [json.dumps({'user': name}) for name in ('a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'b1', 'b2', 'b3')]
        profile = api_profile(path='/records'); profile['statistics'] = {'mode': 'captured'}
        self.popup([profile], capturedLogs=logs)
        top = self.page.locator('#statistics-top-values')
        expect(top).to_have_value('5')
        top.fill('10')
        top.dispatch_event('change')
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('a1', timeout=10000)
        self.assertEqual(10, len(self.stored('fieldStatistics')[0]['fields'][0]['topValues']))
        self.page.reload()
        expect(self.page.locator('#statistics-top-values')).to_have_value('10')

    def test_statistics_skip_records_that_cannot_be_read(self):
        # One linked record answers 404: the others are still summarized.
        self.popup([api_profile(path='/records')])
        records = [json.dumps({'user': 'alice'}), json.dumps({'user': 'bob'})]
        self.context.route('**/fetch-siem-logs', lambda route: route.fulfill(json={
            'logs': records, 'record_logs': records, 'failed': 1, 'errors': ['HTTP 404 from the record API'],
            'available_total': 3, 'limited': False}))
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#statistics-list')).to_contain_text('alice', timeout=10000)
        expect(self.page.locator('#status-text')).to_contain_text('1 record could not be read and was left out')
        stat = self.stored('fieldStatistics')[0]
        self.assertEqual((2, 1), (stat['sampled'], stat['failed']))
        self.assertIn('1 record could not be read and is not counted (HTTP 404 from the record API)', stat['sourceDescription'])
        expect(self.page.locator('#statistics-list summary')).to_contain_text('2 records · 1 field · 1 not read')

    def test_statistics_explain_when_no_record_could_be_read(self):
        self.popup([api_profile(path='/records')])
        self.context.route('**/fetch-siem-logs', lambda route: route.fulfill(json={
            'logs': [], 'record_logs': [], 'failed': 2, 'errors': ['HTTP 404 from the record API'], 'available_total': 2, 'limited': False}))
        self.page.locator('#extract-stats-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text(
            'Statistics: None of the 2 records could be read (HTTP 404 from the record API)', timeout=10000)
        self.assertFalse(self.stored('fieldStatistics'))

    def test_cancel_stops_a_background_extraction(self):
        self.popup([api_profile()])
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#loading-hint')).to_be_visible()
        expect(self.page.locator('#loading-hint')).to_contain_text('continues if you close the popup')
        self.page.locator('#loading-dismiss-btn').click()
        expect(self.page.locator('#status-text')).to_contain_text('Extraction cancelled', timeout=10000)
        self.assertIsNone(self.stored('extractionJob'))
        self.assertNotIn('alice', self.page.locator('#logs-textarea').input_value())

    def test_a_result_that_finished_while_closed_is_added_on_opening(self):
        result = {'id': 'done', 'kind': 'extract', 'label': 'search', 'profileId': 'Slow API', 'profileName': 'Slow API',
                  'tab': {'id': 17, 'url': 'https://console.test/events'},
                  'data': {'logs': [json.dumps({'user': 'finished-while-closed'})], 'failed': 0, 'total': 1, 'info': 'configured API request'}}
        self.popup([api_profile()], extractionResult=result)
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('finished-while-closed'), timeout=10000)
        self.assertIsNone(self.stored('extractionResult'))
        self.page.reload()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('finished-while-closed'))
        self.assertEqual(1, self.page.locator('#logs-textarea').input_value().count('finished-while-closed'))

    def test_an_error_from_a_closed_popup_is_shown_once(self):
        self.popup([api_profile()], extractionError={'id': 'failed', 'kind': 'extract', 'message': 'Synthetic API failure'})
        expect(self.page.locator('#status-text')).to_contain_text('Synthetic API failure')
        self.assertIsNone(self.stored('extractionError'))

    def test_the_popup_runs_the_job_when_the_background_does_not_take_it(self):
        # An extension updated on disk but not reloaded keeps its previous
        # background worker, which does not answer START_EXTRACTION.
        self.popup([api_profile(path='/records')])
        self.page.evaluate("""() => { const send = browser.runtime.sendMessage;
            browser.runtime.sendMessage = m => m.type === 'START_EXTRACTION' ? Promise.resolve(undefined) : send(m); }""")
        self.page.locator('#extract-btn').click()
        expect(self.page.locator('#logs-textarea')).to_have_value(re.compile('alice'), timeout=10000)
        expect(self.page.locator('#status-text')).to_contain_text('Extracted 2 log(s)')
        self.assertIsNone(self.stored('extractionJob'))

    def test_a_job_whose_popup_closed_is_reported_instead_of_waiting(self):
        job = {'id': 'popup-job', 'kind': 'extract', 'label': 'search', 'runner': 'popup',
               'startedAt': 0, 'heartbeat': int(time.time() * 1000) - 60000}
        self.popup([api_profile()], extractionJob=job)
        expect(self.page.locator('#status-text')).to_contain_text('stopped when the popup closed', timeout=10000)
        self.assertIsNone(self.stored('extractionJob'))
        expect(self.page.locator('#extract-btn')).to_be_enabled()

    def test_native_older_worker_falls_back_to_the_popup(self):
        with self.native_extension() as native:
            worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
            extension_id = worker.url.split('/')[2]
            native.route('http://localhost:8000/**', lambda route: route.continue_(
                url=route.request.url.replace('http://localhost:8000', self.url)))
            native.route('**/test/old-worker-source', lambda route: route.fulfill(content_type='text/html', body='<p>Search page</p>'))
            source = native.new_page(); source.goto(self.url + '/test/old-worker-source')
            profile = api_profile(host='127.0.0.1', path='/records'); profile['websiteUrl'] = self.url
            worker.evaluate('p => chrome.storage.local.set({connectorProfiles: [p], capturedLogs: []})', profile)
            worker.evaluate('() => { VeiluxExtractionJobs.start = () => undefined; }')  # behaves like a worker without the handler
            tab = worker.evaluate('url => chrome.tabs.query({}).then(t => t.find(p => p.url === url))', source.url)
            popup = native.new_page(); popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#logs-textarea')).to_have_value(re.compile('alice'), timeout=15000)
            expect(popup.locator('#status-text')).to_contain_text('Extracted 2 log(s)')

    def test_native_extraction_keeps_running_after_the_popup_closes(self):
        with self.native_extension() as native:
            worker = native.service_workers[0] if native.service_workers else native.wait_for_event('serviceworker', timeout=10000)
            extension_id = worker.url.split('/')[2]
            native.route('http://localhost:8000/**', lambda route: route.continue_(
                url=route.request.url.replace('http://localhost:8000', self.url)))
            native.route('**/test/slow-source', lambda route: route.fulfill(content_type='text/html', body='<p>Search page</p>'))
            source = native.new_page(); source.goto(self.url + '/test/slow-source')
            profile = api_profile(host='127.0.0.1'); profile['websiteUrl'] = self.url
            worker.evaluate('p => chrome.storage.local.set({connectorProfiles: [p], capturedLogs: []})', profile)
            tab = worker.evaluate('url => chrome.tabs.query({}).then(t => t.find(p => p.url === url))', source.url)
            popup = native.new_page(); popup.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            popup.locator('#extract-btn').click()
            expect(popup.locator('#loading-hint')).to_be_visible()
            for _ in range(50):
                if worker.evaluate('() => chrome.storage.local.get("extractionJob").then(s => !!s.extractionJob)'):
                    break
                time.sleep(0.1)
            popup.close()  # the slow API is still answering
            for _ in range(150):
                if worker.evaluate('() => chrome.storage.local.get("extractionResult").then(s => !!s.extractionResult)'):
                    break
                time.sleep(0.1)
            stored = worker.evaluate('() => chrome.storage.local.get(["extractionResult", "extractionJob"])')
            self.assertIsNone(stored.get('extractionJob'))
            self.assertIn('alice', json.dumps(stored['extractionResult']['data']['logs']))
            reopened = native.new_page(); reopened.goto(f'chrome-extension://{extension_id}/popup.html?tabId={tab["id"]}')
            expect(reopened.locator('#logs-textarea')).to_have_value(re.compile('alice'), timeout=10000)
            expect(reopened.locator('#status-text')).to_contain_text('Extracted 2 log(s)')
            self.assertIsNone(worker.evaluate('() => chrome.storage.local.get("extractionResult").then(s => s.extractionResult)'))


if __name__ == '__main__':
    unittest.main()
