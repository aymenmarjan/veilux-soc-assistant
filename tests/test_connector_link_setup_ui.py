"""Value-source setup errors identify their field before any page read or external request."""
import unittest
from playwright.sync_api import expect
import test_connector_page_sources_ui as harness


class LinkSetupTests(unittest.TestCase):
    setUpClass=classmethod(harness.PageSourceTests.setUpClass.__func__)
    tearDownClass=classmethod(harness.PageSourceTests.tearDownClass.__func__)
    setUp=harness.PageSourceTests.setUp
    tearDown=harness.PageSourceTests.tearDown
    install_background=harness.PageSourceTests.install_background
    settings=harness.PageSourceTests.settings
    api_form=harness.PageSourceTests.api_form
    tab=harness.PageSourceTests.tab
    value=harness.PageSourceTests.value
    edit=harness.PageSourceTests.edit

    def links(self,**fields):
        self.api_form()
        card=self.value('links',site='other',website='https://cases.test',**fields)
        self.tab('https://cases.test/tickets/4821',
            '<a href="https://console.test/records/events-index/evt%2042">View log</a>')
        return card

    def test_missing_link_pattern_identifies_fix_before_dom_or_http(self):
        card=self.links()
        self.page.evaluate("()=>{window.domReads=0;browser.scripting.executeScript=async()=>{domReads++;throw Error('Unexpected page read');};}")
        self.page.locator('#preview-connector').click()
        expect(card.locator('[data-key=template]')).to_have_attribute('aria-invalid','true')
        expect(card).to_contain_text('replace each changing part with {name}')
        self.assertEqual(0,self.page.evaluate('domReads'))
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_link_pattern_test_save_and_actual_request(self):
        template='https://console.test/records/{index}/{doc_id}'
        card=self.links(template=template)
        self.page.locator('#conn-api-path').fill('/records/${doc_id}')
        self.page.locator('#conn-api-query').fill('{"index":"${index}"}')
        card.get_by_role('button',name='Test on the open page').click()
        expect(card.locator('.value-result')).to_contain_text('evt 42')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())
        self.page.locator('#save-connector').click()
        self.edit()
        expect(self.page.locator('.value-card [data-key=template]')).to_have_value(template)
        self.page.locator('#preview-connector').click()
        expect(self.page.locator('#connector-preview-result')).to_contain_text('2 records read',timeout=10000)
        sent=self.page.request.get(self.url+'/test/sent').json()
        self.assertEqual(1,len(sent));self.assertIn('/records/evt%2042?index=events-index',sent[0]['url'])

    def test_regex_links_to_any_host(self):
        card=self.links(patternType='regex',regex=r'/records/(?<index>[^/?#]+)/(?<doc_id>[^/?#]+)',linkHost='*')
        self.page.locator('#conn-api-path').fill('/records/${doc_id}')
        self.page.locator('#conn-siem-address').fill('https://elsewhere.test')
        card.get_by_role('button',name='Test on the open page').click()
        expect(card.locator('.value-result')).to_contain_text('events-index')

    def test_invalid_regex_focuses_its_field_and_unused_pattern_is_ignored(self):
        card=self.links(patternType='regex',regex='/doc/(.*)')
        card.get_by_role('button',name='Test on the open page').click()
        regex=card.locator('[data-key=regex]')
        expect(regex).to_have_attribute('aria-invalid','true')
        expect(regex).to_be_focused()
        expect(card.locator('.value-result')).to_contain_text('Name the captured values')
        # Switching to an address pattern ignores the hidden regular expression.
        card.locator('[data-key=patternType]').select_option('template')
        card.locator('[data-key=template]').fill('https://console.test/records/{index}/{id}')
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.page.locator('#save-connector').click()
        expect(self.page.locator('#connector-list')).to_contain_text('Portable SOC')
        self.assertEqual([],self.page.request.get(self.url+'/test/sent').json())

    def test_two_link_sources_on_one_page_are_rejected(self):
        self.links(template='https://console.test/a/{id}')
        second=self.value('links',template='https://console.test/b/{id}')
        self.page.locator('#conn-api-path').fill('/records/${id}')
        self.page.locator('#save-connector').click()
        expect(second.locator('[data-key=patternType]')).to_have_attribute('aria-invalid','true')
        expect(second).to_contain_text('one “Links on a page” source per page')


if __name__ == '__main__':
    unittest.main()
