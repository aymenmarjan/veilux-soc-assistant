"""Tools -> Case indicators: every indicator in the case's logs, checked,
copied defanged and exported."""
import csv
import io
import json
import unittest
from playwright.sync_api import expect
import test_extension_ui as harness
from backend_key import AUTH

LOGS = ['{"user":"alice","src_ip":"10.1.2.3","dst_ip":"198.51.100.212","host":"WS-0142.corp.local",'
        '"url":"https://bad.example.net/x?a=1","sha256":"' + 'ab' * 32 + '","email":"bob@example.org"}',
        'logon from 198.51.100.212 again']


class IndicatorTests(unittest.TestCase):
    setUpClass = classmethod(harness.ExtensionUITests.setUpClass.__func__)
    tearDownClass = classmethod(harness.ExtensionUITests.tearDownClass.__func__)
    setUp = harness.ExtensionUITests.setUp
    tearDown = harness.ExtensionUITests.tearDown
    install_background = harness.ExtensionUITests.install_background

    def open_list(self):
        page = self.page
        page.evaluate("Object.defineProperty(navigator, 'clipboard', {value:{writeText:async text=>{window.copied=text}},configurable:true})")
        page.locator('#logs-textarea').fill('\n---LOG SEPARATOR---\n'.join(LOGS))
        page.locator('#stage-tab-tools').click()
        expect(page.locator('#indicators-toggle')).to_have_attribute('aria-selected', 'true')
        expect(page.locator('.ind-row').first).to_be_visible(timeout=15000)
        return page.locator('.ind-row')

    def test_lists_filters_copies_and_exports(self):
        page = self.page
        rows = self.open_list()
        values = rows.locator('.ind-value').all_text_contents()
        for value in ('198.51.100.212', '10.1.2.3', 'bad.example.net', 'https://bad.example.net/x?a=1', 'ab' * 32,
                      'bob@example.org', 'alice', 'WS-0142.corp.local'):
            self.assertIn(value, values)
        expect(page.locator('#indicators-count')).to_have_text(str(len(values)))
        expect(page.locator('#stage-sum-tools')).to_have_text('%d indicators' % len(values))
        repeated = rows.filter(has_text='198.51.100.212').first
        expect(repeated.locator('.ind-count')).to_have_text('×2')
        expect(rows.filter(has_text='10.1.2.3').locator('.ind-scope')).to_have_text('internal')
        # Only public IPs, domains, URLs and hashes can be checked.
        checkable = 5  # 198.51.100.212, bad.example.net, example.org, the URL and the hash
        expect(page.locator('#indicators-check')).to_have_text('Check all (%d)' % checkable)

        page.locator('#indicators-type').select_option('ip')
        expect(rows).to_have_count(2)
        page.locator('#indicators-select-all').check()
        expect(page.locator('#indicators-check')).to_have_text('Check selected (1)')
        page.locator('#indicators-copy').click()
        self.assertEqual('198[.]51[.]100[.]212\n10[.]1[.]2[.]3', page.evaluate('window.copied'))
        page.locator('#indicators-copy-plain').click()
        self.assertEqual('198.51.100.212\n10.1.2.3', page.evaluate('window.copied'))

        page.locator('#indicators-type').select_option('')
        # Two rows stay selected, so "All" shows as partly checked; one click selects everything, a second clears it.
        expect(page.locator('#indicators-select-all')).to_have_js_property('indeterminate', True)
        page.locator('#indicators-select-all').check()
        expect(page.locator('#indicators-check')).to_have_text('Check selected (%d)' % checkable)
        page.locator('#indicators-select-all').uncheck()
        page.locator('#indicators-copy').click()
        copied = page.evaluate('window.copied')
        self.assertIn('hxxps://bad[.]example[.]net/x?a=1', copied)
        self.assertIn('bob[@]example[.]org', copied)
        self.assertNotIn('https://', copied)

        with page.expect_download() as download:
            page.locator('#indicators-csv').click()
        table = list(csv.DictReader(io.StringIO(open(download.value.path(), encoding='utf-8').read())))
        self.assertEqual(len(values), len(table))
        url = next(row for row in table if row['type'] == 'URL')
        self.assertEqual(('https://bad.example.net/x?a=1', 'hxxps://bad[.]example[.]net/x?a=1', 'public'),
                         (url['value'], url['defanged'], url['scope']))

        # The list stays with the case.
        page.reload()
        page.locator('#stage-tab-tools').click()
        expect(page.locator('.ind-row')).to_have_count(len(values))

    def test_selected_indicators_are_checked_and_join_the_case(self):
        page = self.page
        rows = self.open_list()
        page.locator('#manual-ti-vt').uncheck()
        page.locator('#manual-ti-abuse').uncheck()
        page.locator('#indicators-toggle').click()
        rows.filter(has_text='198.51.100.212').locator('input').check()
        expect(page.locator('#indicators-check')).to_have_text('Check selected (1)')
        page.locator('#indicators-check').click()
        expect(page.locator('#status-text')).to_contain_text('Checked 1 indicator', timeout=15000)
        expect(rows.filter(has_text='198.51.100.212').locator('.ind-verdict')).to_be_visible()
        sent = [r['url'] for r in self.page.request.get(self.url + '/test/sent').json()]
        self.assertTrue(any('rdap.org' in url and '198.51.100.212' in url for url in sent), sent)
        self.assertFalse(any('10.1.2.3' in url for url in sent))
        # The lookup joins the case's threat intelligence and its record of what was sent.
        page.locator('#stage-tab-results').click()
        page.locator('#tab-ti').click()
        expect(page.locator('#threat-intel-findings')).to_contain_text('198.51.100.212')
        record = page.evaluate("() => caseStorage.get('sendRecord').then(s => s.sendRecord)")
        self.assertEqual('ioc-check', record[-1]['purpose'])

    def test_backend_lists_and_types_indicators(self):
        response = self.page.request.post(self.url + '/indicators', data=json.dumps({'logs': LOGS}),
                                          headers={'Content-Type': 'application/json', **AUTH})
        items = {item['value']: item for item in response.json()['indicators']}
        self.assertEqual(('ip', 'public', True), (items['198.51.100.212']['type'], items['198.51.100.212']['scope'], items['198.51.100.212']['checkable']))
        self.assertEqual(('ip', 'internal', False), (items['10.1.2.3']['type'], items['10.1.2.3']['scope'], items['10.1.2.3']['checkable']))
        self.assertEqual('user', items['alice']['type'])
        self.assertEqual('host', items['WS-0142.corp.local']['type'])
        self.assertFalse(items['bob@example.org']['checkable'])


if __name__ == '__main__':
    unittest.main()
