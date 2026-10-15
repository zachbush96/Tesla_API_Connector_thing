import io,json,ssl,unittest,urllib.error,urllib.request
from unittest.mock import patch
from tesla_connector.controls import ControlIntent,SPECS
from tesla_connector.signing import checked_request,DisabledSignedProxyTransport,_bounded_roundtrip,verified_tls_opener,MAX_RESPONSE
from tesla_connector.service import SafeError,NoRedirect

class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self,body):self.body=body
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,size):return self.body[:size]
class Opener:
    def __init__(self,response):self.response=response;self.calls=0
    def open(self,request,timeout):
        self.calls+=1
        if isinstance(self.response,Exception):raise self.response
        return self.response
class SigningTests(unittest.TestCase):
    def request(self,action='lock',args=None):
        i=ControlIntent.build('synthetic-owner','AAAAAAAAAAAAAAAAA',action,args or {})
        return urllib.request.Request('https://localhost:4443/api/1/vehicles/'+i.target+'/command/'+i.command,data=i.payload_json,headers={'Authorization':'Bearer synthetic','Content-Type':'application/json'},method='POST')
    def test_allowlist_contract_and_default_no_network(self):
        args={'set_temperature':{'celsius':22},'set_charge_limit':{'percent':80},'set_charging_amps':{'amps':16},'navigation_send':{'destination':'Synthetic address'}}
        with patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('network attempted')):
            for action in ('lock','unlock','climate_start','climate_stop','charge_start','charge_stop','set_charge_limit','set_charging_amps','charge_port_open','charge_port_close','navigation_send','front_trunk','rear_trunk','flash_lights','honk_horn'):
                req=self.request(action,args.get(action));self.assertIs(checked_request(req),req)
                with self.assertRaisesRegex(SafeError,'no network attempted'):DisabledSignedProxyTransport().send(req)
    def test_legacy_proxy_refuses_ambiguous_temperature_endpoint(self):
        with self.assertRaises(SafeError):
            checked_request(self.request('set_temperature', {'celsius':22}))

    def test_host_port_method_query_and_redirect_refused(self):
        for url in ['http://localhost:4443/api/1/vehicles/AAAAAAAAAAAAAAAAA/command/door_lock','https://example.com/api/1/vehicles/AAAAAAAAAAAAAAAAA/command/door_lock','https://localhost:4444/api/1/vehicles/AAAAAAAAAAAAAAAAA/command/door_lock','https://localhost:4443/api/1/vehicles/AAAAAAAAAAAAAAAAA/command/door_lock?x=1','https://localhost:4443/api/1/vehicles/AAAAAAAAAAAAAAAAA/command/wake_up']:
            req=self.request();req.full_url=url;opener=Opener(Response(b'{}'))
            with self.assertRaises(SafeError):_bounded_roundtrip(req,opener)
            self.assertEqual(opener.calls,0)
        req=self.request();req.method='GET'
        with self.assertRaises(SafeError):checked_request(req)
        with self.assertRaises(SafeError):NoRedirect().redirect_request(req,None,302,'',{},'https://example.com')
    def test_authorization_and_extra_headers_refused(self):
        for token in ['', 'Bearer ', 'Bearer synthetic\nprivate','Bearer synthetic token','Basic synthetic']:
            req=self.request();req.add_header('Authorization',token)
            with self.assertRaises(SafeError):checked_request(req)
        req=self.request();req.add_header('X-Forwarded-Host','example.com')
        with self.assertRaises(SafeError):checked_request(req)
    def test_duplicate_noncanonical_and_invalid_payload_refused(self):
        for data in [b'{"extra":true}',b'{"extra":1,"extra":2}',b'[]',b'{ }',b'x'*16385]:
            req=self.request();req.data=data
            with self.assertRaises(SafeError):checked_request(req)
    def test_bounded_result_and_upstream_privacy(self):
        for value in (True,False):
            op=Opener(Response(json.dumps({'response':{'result':value,'reason':'synthetic-private'},'path':'synthetic-private'}).encode()))
            self.assertEqual(_bounded_roundtrip(self.request(),op),{'response':{'result':value}});self.assertEqual(op.calls,1)
    def test_response_type_duplicates_size_and_uncertainty(self):
        for raw in [b'{"response":{"result":1}}',b'{"response":{"result":true,"result":false}}',b'{"response":{"result":NaN}}',b'x'*(MAX_RESPONSE+1),b'not json']:
            op=Opener(Response(raw))
            with self.assertRaisesRegex(SafeError,'no wake or retry'):_bounded_roundtrip(self.request(),op)
            self.assertEqual(op.calls,1)
        for status,ct in [(302,'application/json'),(200,'text/html')]:
            response=Response(b'{}');response.status=status;response.headers={'Content-Type':ct}
            with self.assertRaises(SafeError):_bounded_roundtrip(self.request(),Opener(response))
    def test_failure_categories_no_retries_or_private_error_output(self):
        for code,category in [(401,'authorization-rejected'),(403,'permission-rejected'),(408,'vehicle-asleep-or-offline'),(412,'virtual-key-not-paired'),(429,'rate-limited'),(500,'proxy-rejected')]:
            op=Opener(urllib.error.HTTPError('https://synthetic.invalid/private',code,'synthetic-private',{},io.BytesIO(b'synthetic-private')))
            with self.assertRaisesRegex(SafeError,category) as err:_bounded_roundtrip(self.request(),op)
            self.assertNotIn('synthetic-private',str(err.exception));self.assertEqual(op.calls,1)
        op=Opener(TimeoutError('synthetic-private'))
        with self.assertRaises(SafeError) as err:_bounded_roundtrip(self.request(),op)
        self.assertNotIn('synthetic-private',str(err.exception));self.assertEqual(op.calls,1)
    def test_tls_verification_and_no_proxy_environment(self):
        context=ssl.create_default_context()
        with patch('tesla_connector.signing.private_file',return_value='PUBLIC CERTIFICATE'),patch('tesla_connector.signing.ssl.create_default_context',return_value=context),patch('tesla_connector.signing.urllib.request.build_opener') as build:
            verified_tls_opener('/synthetic/public.pem')
            handlers=build.call_args.args
            self.assertEqual(handlers[0].proxies,{})
            self.assertIs(handlers[1]._context,context);self.assertIsInstance(handlers[2],NoRedirect)
            context.check_hostname=False
            with self.assertRaises(SafeError):verified_tls_opener('/synthetic/public.pem')
        with patch('tesla_connector.signing.private_file',return_value='PRIVATE KEY'),patch('tesla_connector.signing.ssl.create_default_context') as create:
            with self.assertRaises(SafeError):verified_tls_opener('/synthetic/private.pem')
            create.assert_not_called()
