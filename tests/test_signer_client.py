import json,unittest
from email.message import Message
from unittest.mock import patch,Mock
from tesla_connector.remote_controls import SignerMockExecutor,RemoteOperations,RemoteMockMCP,MockRemoteExecutor
from tesla_connector.controls import ControlIntent
from tesla_connector.http_mock import VerifiedIdentity
from tesla_connector.service import Service,Config,SafeError
class Response:
 def __init__(self,raw,status=200):self.raw=raw;self.status=status;self.headers=Message();self.headers['Content-Type']='application/json'
 def __enter__(self):return self
 def __exit__(self,*a):return False
 def read(self,n):return self.raw[:n]
class SignerClientTests(unittest.TestCase):
 def executor(self,body):
  x=object.__new__(SignerMockExecutor);x._token='synthetic-token-'+('a'*64);x._opener=Mock();x._opener.open.return_value=Response(body);return x
 def value(self):return {'action':'lock','simulated':True,'executed':False,'vehicle_execution_verified':False,'execution_enabled':False,'sdk_commit':SignerMockExecutor.SDK_COMMIT,'synthetic_sdk_requests':1,'fleet_network_requests':0,'gross_reserved_microdollars':0}
 def test_fixed_tls_client_mock_contract_and_no_retry(self):
  x=self.executor(json.dumps(self.value()).encode());i=ControlIntent.build('synthetic-owner','AAAAAAAAAAAAAAAAA','lock',{});out=x.execute(i,'a'*32);self.assertFalse(out['executed']);r=x._opener.open.call_args.args[0];self.assertEqual(r.full_url,'https://127.0.0.1:8766/simulate');self.assertEqual(r.method,'POST');self.assertNotIn('approved',r.data.decode());self.assertEqual(x._opener.open.call_count,1)
 def test_changed_live_malformed_duplicate_or_private_error_response_refused(self):
  i=ControlIntent.build('synthetic-owner','AAAAAAAAAAAAAAAAA','lock',{})
  bodies=[b'{"executed":true}',b'{"action":"lock","action":"unlock"}',b'x'*65537]
  for key,val in [('action','unlock'),('execution_enabled',True),('fleet_network_requests',1),('gross_reserved_microdollars',1),('synthetic_sdk_requests',True)]:
   d=self.value();d[key]=val;bodies.append(json.dumps(d).encode())
  for body in bodies:
   x=self.executor(body)
   with self.assertRaises(SafeError):x.execute(i,'a'*32)
   self.assertEqual(x._opener.open.call_count,1)
  x=self.executor(b'');x._opener.open.side_effect=RuntimeError('synthetic-private-token')
  with self.assertRaises(SafeError) as e:x.execute(i,'a'*32)
  self.assertNotIn('synthetic-private',str(e.exception));self.assertEqual(x._opener.open.call_count,1)
 def test_remote_adapter_preserves_injected_read_service_and_notifications(self):
  svc=Service(Config());ops=RemoteOperations('synthetic-owner','AAAAAAAAAAAAAAAAA',executor=MockRemoteExecutor());mcp=RemoteMockMCP('synthetic-owner',ops,service=svc);identity=VerifiedIdentity('synthetic-owner');self.assertIs(mcp.service,svc)
  raw=json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}).encode();self.assertEqual(mcp.post('/mcp',raw,identity)[0],202)
  raw=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'read_temperature','arguments':{}}}).encode();status,v=mcp.post('/mcp',raw,identity);self.assertEqual(status,200);self.assertFalse(v['result']['isError']);self.assertEqual(json.loads(v['result']['content'][0]['text'])['inside_celsius'],19)
 def test_broker_installed_adapter_preserves_service_and_blocks_forged_boolean(self):
  from tesla_connector.broker import Broker
  svc=Service(Config());ops=RemoteOperations('synthetic-owner','AAAAAAAAAAAAAAAAA',executor=MockRemoteExecutor());b=Broker('synthetic-owner','o'*64,'m'*64,service=svc,remote_operations=ops);h={'host':'127.0.0.1:8765','authorization':'Bearer '+'m'*64,'content-type':'application/json'}
  def call(n,args):return b.handle('POST','/mcp',h,json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':n,'arguments':{'expected_control_mode':'mock',**args} if n=='execute_control' else args}}).encode())
  _,_,v=call('prepare_control',{'action':'lock','parameters':{}});op=json.loads(v['result']['content'][0]['text'])['operation_id'];_,_,v=call('execute_control',{'operation_id':op,'approved':True});self.assertTrue(v['result']['isError']);_,_,v=call('execute_control',{'operation_id':op});self.assertFalse(v['result']['isError']);self.assertIs(b.mcp.service,svc)
