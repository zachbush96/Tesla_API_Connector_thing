import concurrent.futures,json,unittest
from tesla_connector.remote_controls import RemoteOperations,RemoteMockMCP,MockRemoteExecutor,REMOTE_TOOLS
from tesla_connector.http_mock import VerifiedIdentity
from tesla_connector.controls import ControlIntent
from tesla_connector.service import SafeError
class RemoteTests(unittest.TestCase):
 def setUp(self):
  self.now=1000.;self.identity=VerifiedIdentity('synthetic-owner');self.mock=MockRemoteExecutor();self.operations=RemoteOperations(self.identity.user_id,'AAAAAAAAAAAAAAAAA',executor=self.mock,clock=lambda:self.now);self.mcp=RemoteMockMCP(self.identity.user_id,self.operations)
 def call(self,name,args,identity=None):

  if name=='execute_control':args={'expected_control_mode':'mock',**args}
  return self.mcp.post('/mcp',json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}).encode(),identity or self.identity)
 def prepare(self):return self.operations.prepare(self.identity,'lock',{})['operation_id']
 def test_remote_mock_needs_no_local_ui_and_uses_one_exact_operation(self):
  status,result=self.call('prepare_control',{'action':'lock','parameters':{}});self.assertEqual(status,200);op=json.loads(result['result']['content'][0]['text'])['operation_id'];status,result=self.call('execute_control',{'operation_id':op});out=json.loads(result['result']['content'][0]['text']);self.assertTrue(out['simulated']);self.assertFalse(out['executed']);self.assertEqual(self.mock.calls,1)
  self.assertTrue(self.call('execute_control',{'operation_id':op})[1]['result']['isError']);self.assertEqual(self.mock.calls,1)
 def test_identity_is_external_and_model_fields_do_not_grant(self):
  message=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list'}).encode()
  self.assertEqual(self.mcp.post('/mcp',message,{'oai-authenticated-user-id':self.identity.user_id})[0],401);self.assertEqual(self.mcp.post('/mcp',message,VerifiedIdentity('other'))[0],403)
  op=self.prepare()
  for args in [{'operation_id':op,'approved':True},{'operation_id':op,'confirmed':True},{'operation_id':op,'owner_id':self.identity.user_id}]:self.assertTrue(self.call('execute_control',args)[1]['result']['isError'])
  self.assertEqual(self.mock.calls,0)
 def test_default_disabled_without_spending_or_live_executor_injection(self):
  ops=RemoteOperations(self.identity.user_id,'AAAAAAAAAAAAAAAAA',clock=lambda:self.now);op=ops.prepare(self.identity,'lock',{})['operation_id']
  with self.assertRaisesRegex(SafeError,'no car request or spending'):ops.execute(self.identity,op,expected_control_mode='mock')
  with self.assertRaises(SafeError):ops.execute(self.identity,op,expected_control_mode='mock')
  with self.assertRaises(SafeError):RemoteOperations(self.identity.user_id,'AAAAAAAAAAAAAAAAA',executor=object())
 def test_expiry_rollback_and_changed_bound_action_refused(self):
  for elapsed in (300,-1):
   op=self.prepare();issued=self.now;self.now+=elapsed
   with self.assertRaises(SafeError):self.operations.execute(self.identity,op,expected_control_mode='mock')
   self.now=issued
  op=self.prepare();old,issued,binding=self.operations.pending[op];self.operations.pending[op]=(ControlIntent.build(old.principal,old.target,'unlock',{}),issued,binding)
  with self.assertRaises(SafeError):self.operations.execute(self.identity,op,expected_control_mode='mock')
  self.assertEqual(self.mock.calls,0)
 def test_concurrent_replay_executes_mock_once(self):
  op=self.prepare()
  def attempt(_):
   try:return self.operations.execute(self.identity,op,expected_control_mode='mock')
   except SafeError:return None
  with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(attempt,range(64)))
  self.assertEqual(sum(r is not None for r in results),1);self.assertEqual(self.mock.calls,1)
 def test_duplicate_json_forged_target_and_raw_commands_refused(self):
  self.assertEqual(self.mcp.post('/mcp',b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}',self.identity)[0],400)
  for args in [{'action':'wake_up','parameters':{}},{'action':'lock','parameters':{'target':'other'}},{'action':'set_temperature','parameters':{'celsius':True}}]:self.assertTrue(self.call('prepare_control',args)[1]['result']['isError'])
 def test_truthful_mock_annotations(self):
  for tool in REMOTE_TOOLS:self.assertFalse(tool['annotations']['readOnlyHint']);self.assertFalse(tool['annotations']['openWorldHint']);self.assertTrue('MOCK' in tool['description'] or tool['description'].startswith('PREPARE ONLY:'))
  self.assertTrue(REMOTE_TOOLS[1]['annotations']['idempotentHint'])
  self.assertEqual(set(REMOTE_TOOLS[1]['inputSchema']['required']),{'operation_id','expected_control_mode'})
 def test_live_mode_assertion_cannot_enable_mock_or_consume_its_proposal(self):
  op=self.prepare()
  self.assertTrue(self.call('execute_control',{'operation_id':op,'expected_control_mode':'live'})[1]['result']['isError'])
  self.assertIn(op,self.operations.pending);self.assertEqual(self.mock.calls,0)
  self.assertFalse(self.call('execute_control',{'operation_id':op})[1]['result']['isError']);self.assertEqual(self.mock.calls,1)
 def test_public_navigation_proposal_redacts_destination_and_identity(self):
  text=json.dumps(self.operations.prepare(self.identity,'navigation_send',{'destination':'Synthetic private destination'}));self.assertNotIn('Synthetic private destination',text);self.assertNotIn('AAAAAAAAAAAAAAAAA',text);self.assertNotIn(self.identity.user_id,text)
