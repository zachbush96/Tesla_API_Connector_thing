import copy
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
from unittest.mock import Mock, MagicMock
from tesla_connector.broker import Broker,ORIGIN
from tesla_connector.keychain import add_tesla_credentials
from tesla_connector.runtime import compose_local_runtime
from tesla_connector.oauth import REDIRECT
from tesla_connector.oauth_transport import TLSOAuthTransport
from tesla_connector.service import SafeError

class SyntheticKeychain:
    def __init__(self):self.records={};self.locked=False
    def get(self,account):
        if self.locked or account not in self.records:raise SafeError('Protected credentials unavailable')
        return copy.deepcopy(self.records[account])
    def put(self,account,value,add_only=False):
        if self.locked or add_only and account in self.records:raise SafeError('Persistence refused')
        self.records[account]=copy.deepcopy(value)

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();Path(self.directory.name).chmod(0o700)
        self.backend=SyntheticKeychain()
        add_tesla_credentials('synthetic-client','synthetic-secret',self.backend)
        self.transport=Mock();self.read=MagicMock()
        response=self.read.open.return_value.__enter__.return_value
        response.read.return_value=json.dumps({'response':{'charge_state':{'battery_level':72,'charge_limit_soc':80,'charging_state':'Stopped','charger_power':0}}}).encode()
    def tearDown(self):self.directory.cleanup()
    def compose(self,**kwargs):
        return compose_local_runtime(self.directory.name,'synthetic-owner','AAAAAAAAAAAAAAAAA',backend=self.backend,oauth_transport=self.transport,read_opener=self.read,**kwargs)
    def reply(self,scopes,refresh=None,access='synthetic-access'):
        return {'access_token':access,'refresh_token':refresh,'scope':scopes,'expires_in':3600}
    def authorize(self,runtime,scopes=('openid','vehicle_device_data')):
        url=runtime.oauth.begin('synthetic-browser',scopes)
        state=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['state'][0]
        return runtime.oauth.callback(REDIRECT+'?'+urllib.parse.urlencode({'state':state,'code':'synthetic-code'}),'synthetic-browser')
    def test_helper_vault_callback_budget_read_full_flow(self):
        runtime=self.compose()
        self.transport.exchange.return_value=self.reply('openid vehicle_device_data')
        broker=Broker('synthetic-owner','o'*32,'m'*32,oauth=runtime.oauth)
        headers={'host':'connector.example.invalid','origin':ORIGIN,'authorization':'Bearer '+'o'*32}
        status,session_headers,body=broker.handle('POST','/operator/session',headers)
        browser={**headers,'cookie':session_headers['Set-Cookie'].split(';')[0],'x-csrf-token':body['csrf']}
        status,redirect,_=broker.handle('POST','/oauth/start',browser)
        self.assertEqual(status,303)
        state=urllib.parse.parse_qs(urllib.parse.urlsplit(redirect['Location']).query)['state'][0]
        status,_,_=broker.handle('GET','/oauth/callback?'+urllib.parse.urlencode({'state':state,'code':'synthetic-code'}),browser)
        self.assertEqual(status,303)
        with self.assertRaises(SafeError):runtime.service.call('read_battery_charging',{})
        self.read.open.assert_not_called() # Default budget zero prevents transport.
        runtime.budget.configure(2000)
        self.assertEqual(runtime.service.call('read_battery_charging',{})['battery_percent'],72)
        self.assertEqual(runtime.budget.spent(),2000)
        with self.assertRaises(SafeError):runtime.service.call('read_battery_charging',{})
        self.assertEqual(self.read.open.call_count,1)
        self.assertNotIn('synthetic-secret',repr(runtime))
    def test_refresh_rotation_survives_recomposition(self):
        runtime=self.compose()
        scopes='openid vehicle_device_data offline_access'
        self.transport.exchange.return_value=self.reply(scopes,'synthetic-refresh-one')
        self.authorize(runtime,scopes.split())
        restarted=self.compose()
        self.transport.exchange.return_value=self.reply(scopes,'synthetic-refresh-two','synthetic-access-two')
        self.assertTrue(restarted.oauth.refresh()['refreshed'])
        self.assertEqual(self.compose().oauth.access_token(),'synthetic-access-two')
    def test_missing_locked_credentials_fail_closed(self):
        self.backend.locked=True
        with self.assertRaises(SafeError):self.compose()
        self.transport.exchange.assert_not_called();self.read.open.assert_not_called()
    def test_scope_and_token_expiry_before_read(self):
        runtime=self.compose()
        self.transport.exchange.return_value=self.reply('openid vehicle_device_data')
        self.authorize(runtime);runtime.budget.configure(4000)
        with self.assertRaises(SafeError):runtime.service.call('read_location',{})
        self.assertEqual(runtime.budget.spent(),0)
        account=next(k for k in self.backend.records if k.startswith('tokens-'))
        self.backend.records[account]['expires_at']=1
        with self.assertRaises(SafeError):runtime.service.call('read_battery_charging',{})
        self.read.open.assert_not_called()
    def test_failed_read_reservation_never_refunded(self):
        runtime=self.compose();self.transport.exchange.return_value=self.reply('openid vehicle_device_data')
        self.authorize(runtime);runtime.budget.configure(2000)
        self.read.open.side_effect=OSError('synthetic-private-details')
        with self.assertRaises(SafeError) as error:runtime.service.call('read_battery_charging',{})
        self.assertNotIn('synthetic-private',str(error.exception));self.assertEqual(runtime.budget.spent(),2000)
    def test_default_transport_disabled_after_entry(self):
        runtime=compose_local_runtime(self.directory.name,'synthetic-owner','AAAAAAAAAAAAAAAAA',backend=self.backend)
        with self.assertRaises(SafeError):self.authorize(runtime)
    def test_tls_adapter_default_and_fixed_request(self):
        opener=MagicMock()
        with self.assertRaises(SafeError):TLSOAuthTransport(opener=opener).exchange('https://evil.invalid',{})
        opener.open.assert_not_called()
        response=opener.open.return_value.__enter__.return_value;response.read.return_value=b'{"access_token":"synthetic"}'
        from tesla_connector.oauth import TOKEN_URL
        adapter=TLSOAuthTransport(approved=True,opener=opener)
        self.assertEqual(adapter.exchange(TOKEN_URL,{'grant_type':'refresh_token','client_id':'synthetic','refresh_token':'synthetic'})['access_token'],'synthetic')
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_method(),'POST');self.assertEqual(opener.open.call_args.kwargs['timeout'],10)
        with self.assertRaises(SafeError):adapter.exchange('https://evil.invalid',{})

    def test_keychain_persistence_failure_blocks_refresh_and_reuse(self):
        runtime=self.compose();scopes='openid vehicle_device_data offline_access'
        self.transport.exchange.return_value=self.reply(scopes,'synthetic-old-refresh')
        self.authorize(runtime,scopes.split())
        original=self.backend.put
        def refuse(account,value,add_only=False):
            if account.startswith('tokens-'):raise RuntimeError('synthetic-private-error')
            return original(account,value,add_only)
        self.backend.put=refuse
        self.transport.exchange.return_value=self.reply(scopes,'synthetic-new-refresh')
        with self.assertRaises(SafeError):runtime.oauth.refresh()
        with self.assertRaises(SafeError):runtime.oauth.access_token()
        self.assertEqual(self.transport.exchange.call_count,2)
        with self.assertRaises(SafeError):runtime.oauth.refresh()
        self.assertEqual(self.transport.exchange.call_count,2)

    def test_tls_bounds_invalid_json_and_form(self):
        from tesla_connector.oauth import TOKEN_URL
        opener=MagicMock();adapter=TLSOAuthTransport(approved=True,opener=opener)
        with self.assertRaises(SafeError):adapter.exchange(TOKEN_URL,{'grant_type':'refresh_token','client_id':'synthetic'})
        opener.open.assert_not_called()
        form={'grant_type':'refresh_token','client_id':'synthetic','refresh_token':'synthetic'}
        response=opener.open.return_value.__enter__.return_value
        for raw in (b'x'*65537,b'{"bad":NaN}',b'[]'):
            response.read.return_value=raw
            with self.assertRaises(SafeError):adapter.exchange(TOKEN_URL,form)
