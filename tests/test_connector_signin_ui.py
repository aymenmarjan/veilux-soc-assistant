"""The editor preserves explicit auth choices and sends full session cookies only to the configured API."""
import unittest
from playwright.sync_api import expect
import test_connector_setup_ui as harness


class ConnectorSignInTests(unittest.TestCase):
    setUpClass=classmethod(harness.ConnectorSetupTests.setUpClass.__func__)
    tearDownClass=classmethod(harness.ConnectorSetupTests.tearDownClass.__func__)
    setUp=harness.ConnectorSetupTests.setUp
    tearDown=harness.ConnectorSetupTests.tearDown
    install_background=harness.ConnectorSetupTests.install_background
    settings=harness.ConnectorSetupTests.settings
    api_form=harness.ConnectorSetupTests.api_form
    tab=harness.ConnectorSetupTests.tab

    def test_opensearch_preset_uses_current_login_and_correct_health_path(self):
        self.api_form();self.page.locator('#conn-preset').select_option('opensearch')
        expect(self.page.locator('#conn-auth-type')).to_have_value('browser_session')
        self.page.locator('#conn-siem-base-url').fill('https://records.test')
        self.page.evaluate('''()=>{window.cookieReads=[];browser.cookies={getAll:async options=>{
          cookieReads.push(options);return [{name:'session',value:'main'},
          {name:'session_part.0',value:'part0'},{name:'session_part.1',value:'part1'}];}};}''')
        payloads=[]
        self.page.on('request',lambda r:payloads.append(r.post_data_json) if r.url.endswith('/test-siem') else None)
        self.page.locator('#test-connector').click()
        expect(self.page.locator('#connector-test-result')).to_contain_text('Connection check succeeded',timeout=10000)
        self.assertEqual('/api/status',payloads[0]['test_path'])
        self.assertEqual({'session':'main','session_part.0':'part0','session_part.1':'part1'},payloads[0]['auth_cookies'])
        self.assertEqual([{'url':'https://records.test'}],self.page.evaluate('cookieReads'))
        self.assertTrue(payloads[0]['verify_ssl'])

    def test_existing_named_cookie_setting_is_preserved_and_can_be_switched(self):
        self.api_form();self.page.locator('#conn-auth-type').select_option('cookie')
        self.page.locator('#conn-cookie-name').fill('my_session');self.page.locator('#save-connector').click()
        self.page.locator('#connector-list .prompt-item').filter(has_text='Portable SOC').get_by_role('button',name='Edit Portable SOC').click()
        expect(self.page.locator('#conn-auth-type')).to_have_value('cookie')
        expect(self.page.locator('#conn-cookie-name')).to_have_value('my_session')
        expect(self.page.locator('#conn-auth-help')).to_contain_text('Use my current browser login')
        self.page.locator('#conn-auth-type').select_option('browser_session')
        expect(self.page.locator('#conn-auth-help')).to_contain_text('keep a tab open')
        expect(self.page.locator('#conn-cookie-name')).not_to_be_visible()
        self.page.locator('#save-connector').click()
        self.page.locator('#connector-list .prompt-item').filter(has_text='Portable SOC').get_by_role('button',name='Edit Portable SOC').click()
        expect(self.page.locator('#conn-auth-type')).to_have_value('browser_session')

    def test_health_path_is_never_guessed(self):
        self.api_form()
        values=self.page.evaluate('''async()=>{const profile={schemaVersion:2,auth:{type:'none'},api:{}};
          return [(await VeiluxConnectorClient.requestPayload(profile)).test_path,
          (await VeiluxConnectorClient.requestPayload({...profile,platform:'opensearch'})).test_path,
          (await VeiluxConnectorClient.requestPayload({...profile,platform:'opensearch',api:{testPath:'/custom/check'}})).test_path];}''')
        # A blank check path is "/" on every platform; templates write their own.
        self.assertEqual(['/','/','/custom/check'],values)

    def test_backend_override_survives_save_and_reopen(self):
        self.api_form();self.page.locator('#conn-auth-type').select_option('browser_session')
        self.page.locator('#conn-more > summary').click()
        self.page.locator('#conn-execute-via').select_option('backend')
        self.page.locator('#save-connector').click()
        self.page.locator('#connector-list .prompt-item').filter(has_text='Portable SOC').get_by_role('button',name='Edit Portable SOC').click()
        expect(self.page.locator('#conn-execute-via')).to_have_value('backend')
        expect(self.page.locator('#conn-auth-type')).to_have_value('browser_session')
