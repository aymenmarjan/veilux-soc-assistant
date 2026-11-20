import unittest
from playwright.sync_api import expect
import test_ui_redesign as harness

STATS=[{'indexPattern':'events-*','sampled':2,'total':2,'fields':[
    {'field':'User','count':2,'percentage':100,'topValues':[{'value':'statistics-alice','count':2,'percentage':100}]}]}]

class StatisticsChangesUITests(unittest.TestCase):
    setUpClass=classmethod(harness.InterfaceUITests.setUpClass.__func__)
    tearDownClass=classmethod(harness.InterfaceUITests.tearDownClass.__func__)
    setUp=harness.InterfaceUITests.setUp
    tearDown=harness.InterfaceUITests.tearDown
    install_background=harness.InterfaceUITests.install_background
    store=harness.InterfaceUITests.store
    stored=harness.InterfaceUITests.stored
    clipboard=harness.InterfaceUITests.clipboard

    def test_clear_removes_statistics_sources_and_saved_results(self):
        self.store({'fieldStatistics':STATS,'fieldStatisticsPages':[{'url':'https://source.test/stats','title':'Statistics source'}]})
        self.page.reload()
        self.install_background()
        self.page.locator('#clear-btn').click()
        expect(self.page.locator('#statistics-section')).to_be_hidden()
        expect(self.page.locator('#analyze-btn')).to_be_disabled()
        self.assertEqual([],self.stored('fieldStatistics'))
        self.assertEqual([],self.stored('fieldStatisticsPages'))
        self.page.reload()
        expect(self.page.locator('#statistics-list article')).to_have_count(0)
        expect(self.page.locator('#source-summary')).to_have_text('Paste logs or extract from a source page.')

    def test_real_statistics_only_sanitization_maps_copies_and_persists(self):
        self.clipboard()
        self.store({'capturedLogs':[],'fieldStatistics':STATS,'enablePatternSanitization':True})
        self.page.reload()
        self.install_background()
        self.clipboard()
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator('#enable-pattern').check()
        self.page.locator('#analyze-btn').click()
        expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
        expect(self.page.locator('#sanitized-statistics-textarea')).to_be_visible()
        value=self.page.locator('#sanitized-statistics-textarea').input_value()
        self.assertNotIn('statistics-alice',value)
        self.assertIn('⟦USER#',value)
        expect(self.page.locator('#sanitized-section')).to_be_hidden()
        self.page.locator('#copy-sanitized-statistics-btn').click()
        self.assertEqual(value,self.page.evaluate('window.copied'))
        self.page.locator('#tab-changes').click()
        self.page.locator('#mapping-toggle').click()
        expect(self.page.locator('#mapping-table')).to_contain_text('statistics-alice')
        self.page.locator('#copy-mapping-btn').click()
        self.assertIn('statistics-alice',self.page.evaluate('window.copied'))
        self.page.reload()
        self.assertEqual(value,self.page.locator('#sanitized-statistics-textarea').input_value())
        self.page.locator('#clear-btn').click()
        self.assertIsNone(self.stored('lastSanitizedStatistics'))
        expect(self.page.locator('#results-workspace')).to_be_hidden()

    def test_mixed_statistics_stay_out_of_editable_logs_on_second_run(self):
        self.store({'capturedLogs':['event-only'],'fieldStatistics':STATS,'enablePatternSanitization':True})
        self.page.reload()
        self.install_background()
        calls=[]
        self.page.on('request',lambda request:calls.append(request.post_data_json) if request.url.endswith('/analyze') else None)
        self.page.locator('input[value="sanitize_only"]').check()
        self.page.locator('#enable-pattern').check()
        for _ in range(2):
            self.page.locator('#analyze-btn').click()
            expect(self.page.locator('#loading-overlay')).to_be_hidden(timeout=15000)
            expect(self.page.locator('#sanitized-textarea')).to_have_value('event-only')
            expect(self.page.locator('#sanitized-statistics-textarea')).to_be_visible()
        self.assertEqual(2,len(calls))
        self.assertTrue(all(call['logs']==['event-only'] and call['field_statistics']==STATS for call in calls))
