"""Remote owner MCP staging. Operation IDs prevent replay, not prove consent.

Explicit user authorization is enforced by host/assistant policy. VerifiedIdentity
comes from trusted hosting, never a model field. No local GUI or live executor.
"""
import contextlib,functools,http.client,io,json,secrets,socket,threading,time,ssl,urllib.request,urllib.error
from contextvars import ContextVar,copy_context
from .service import private_file
from .controls import canonical
from .audit import strict_object
from .controls import ControlIntent,SPECS
from .storage import digest
from .control_catalog import typed_tools,CATALOG,ceiling,parameters as typed_parameters,redacted
from .http_mock import VerifiedIdentity,MockHTTPMCP
from .mcp import TOOLS
from .service import SafeError,arguments
from .signing_diagnostics import (SanitizedSigningError, checked_diagnostic,
    local_transport, UPSTREAM_ERROR, TransportEvidenceError)

REMOTE_TOOLS=[
 {'name':'prepare_control','description':'STAGED REMOTE MOCK: prepare an exact control proposal for the configured vehicle. No car call or wake; no Mac interaction. Owner authentication required. Does not establish human consent.',
  'inputSchema':{'type':'object','properties':{'action':{'type':'string','enum':list(SPECS)},'parameters':{'type':'object','properties':{'celsius':{'type':'number','minimum':15,'maximum':28},'percent':{'type':'integer','minimum':50,'maximum':100},'amps':{'type':'integer','minimum':1,'maximum':48},'destination':{'type':'string','minLength':1,'maxLength':300}},'additionalProperties':False}},'required':['action','parameters'],'additionalProperties':False},
  'annotations':{'readOnlyHint':False,'destructiveHint':False,'idempotentHint':False,'openWorldHint':False}},
 {'name':'execute_control','description':'STAGED REMOTE MOCK ONLY: consume one exact expiring operation ID. No physical execution, car request or spending. Invoke only for an explicitly owner-requested/confirmed action under host assistant policy. No approved/confirmed boolean accepted. Live execution disabled.',
  'inputSchema':{'type':'object','properties':{'operation_id':{'type':'string','pattern':'^[a-f0-9]{32}$'},'expected_control_mode':{'type':'string','enum':['mock','live'],'description':'Assert the configured mode; never enables execution or proves consent. The Sites gateway supplies this internal field.'}},'required':['operation_id','expected_control_mode'],'additionalProperties':False},
  'annotations':{'readOnlyHint':False,'destructiveHint':False,'idempotentHint':True,'openWorldHint':False}},
]
REMOTE_TOOLS[0]['inputSchema']['properties']['parameters']={'type':'object','description':'Use a typed prepare tool for the exact command parameter schema.'}
REMOTE_TOOLS+=typed_tools()
LIVE_REMOTE_TOOLS=json.loads(json.dumps(REMOTE_TOOLS))
LIVE_REMOTE_TOOLS[0]['description']='Prepare one exact expiring control proposal for the configured owner vehicle. No car request or spending during preparation. Live execution requires a separate owner-requested or confirmed execute_control under host assistant policy. Estimate includes fresh safety preflight and every outgoing attempt.'
LIVE_REMOTE_TOOLS[1]['description']='Consume one exact expiring operation ID and matching owner-local one-action grant for the explicitly owner-requested or confirmed action. May change the physical vehicle and reserve the existing lifetime budget. Exact target, payload, scopes, matched key and documented action prerequisites are enforced locally; Park is required only for horn, lights and charge-port opening. Submission acceptance does not verify physical effect. No approved/confirmed model boolean, automatic retry or wake.'
LIVE_REMOTE_TOOLS[1]['annotations']['destructiveHint']=True
LIVE_REMOTE_TOOLS[1]['annotations']['openWorldHint']=True
LIVE_REMOTE_TOOLS[1]['annotations']['idempotentHint']=False
class MockRemoteExecutor:
 def __init__(self):self.calls=0
 def execute(self,intent,operation_id=None):
  intent.validated();self.calls+=1
  return {'action':intent.action,'simulated':True,'executed':False,'vehicle_execution_verified':False,'execution_enabled':False}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

_SIGNER_WORKFLOW_SECONDS=60.0
_SIGNER_TRANSPORT_SECONDS=55.0
_SIGNER_FINAL_JOURNAL_SECONDS=4.0
_SIGNER_WORKFLOW_DEADLINE=ContextVar('local_signer_workflow_deadline',default=None)

def _workflow_remaining():
 deadline=_SIGNER_WORKFLOW_DEADLINE.get()
 if deadline is None:return None
 remaining=deadline-time.monotonic()
 if remaining<=0:raise TimeoutError('Local signing deadline exceeded; outcome unconfirmed; no retry')
 return remaining

def _signer_workflow(function):
 """One absolute caller budget; nested public entry points cannot extend it."""
 @functools.wraps(function)
 def bounded(*args,**kwargs):
  deadline=time.monotonic()+_SIGNER_WORKFLOW_SECONDS
  outer=_SIGNER_WORKFLOW_DEADLINE.get()
  if outer is not None:deadline=min(deadline,outer)
  token=_SIGNER_WORKFLOW_DEADLINE.set(deadline)
  try:return function(*args,**kwargs)
  finally:_SIGNER_WORKFLOW_DEADLINE.reset(token)
 return bounded

class _SignerReadFailure(Exception):
 """Internal class-only cause and fixed progress; never contains response text."""
 def __init__(self,error,stage,status):
  super().__init__('Local signing transport failed; private details withheld')
  self.error,self.stage,self.status=error,stage,status

class _SignerExchange:
 """Cancel one connection/read, with no callback or journal work in its thread."""
 def __init__(self,deadline,cancel_check=None):
  self.deadline=deadline;self.cancelled=threading.Event();self.done=threading.Event()
  self.cancel_check=cancel_check
  self.cancel_context=copy_context()
  self.lock=threading.Lock();self.connection=None;self.sock=None
  self.stage='http_initiated';self.status=0;self.result=None;self.error=None
 def check(self):
  if self.cancel_check is not None:self.cancel_context.copy().run(self.cancel_check)
  if self.cancelled.is_set() or time.monotonic()>=self.deadline:
   raise TimeoutError('Local signing deadline exceeded; outcome unconfirmed; no retry')
 def track(self,connection):
  self.check()
  with self.lock:self.connection=connection
  self.check()
 def track_socket(self,sock):
  with self.lock:self.sock=sock
  self.check()
 def received(self,status):
  self.check()
  with self.lock:
   self.stage='response_received'
   self.status=status if type(status)is int and 100<=status<=599 else 0
 def progress(self):
  with self.lock:return self.stage,self.status
 def abort(self):
  self.cancelled.set()
  with self.lock:
   connection,sock=self.connection,self.sock
  # shutdown wakes both header and body reads, even while HTTPResponse holds
  # its own reference. Avoid response.close() here: a concurrent buffered read
  # can hold that object's lock. The worker owns response cleanup instead.
  if sock is None and connection is not None:sock=connection.sock
  if sock is not None:
   try:sock.shutdown(socket.SHUT_RDWR)
   except Exception:pass
   try:sock.close()
   except Exception:pass

class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
 def __init__(self,*args,exchange,**kwargs):
  self.exchange=exchange
  super().__init__(*args,**kwargs)
  exchange.track(self)
 def connect(self):
  self.exchange.check()
  super().connect()
  try:self.exchange.track_socket(self.sock)
  except Exception:
   self.close();raise
 def send(self,data):
  # DNS/TLS completion after cancellation can never send an HTTP request.
  self.exchange.check()
  return super().send(data)

class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
 def __init__(self,context,exchange,host='127.0.0.1:8766'):
  super().__init__(context=context);self.exchange=exchange;self.host=host
 def https_open(self,request):
  if request.host!=self.host or request.type!='https':raise SafeError('Fixed HTTPS origin required')
  def connection(*args,**kwargs):
   return _DeadlineHTTPSConnection(*args,exchange=self.exchange,**kwargs)
  return self.do_open(connection,request,context=self._context)

class _PinnedSignerOpener:
 """The existing certificate context, fixed loopback, no proxy/redirect/retry."""
 def __init__(self,context):self.context=context
 def for_exchange(self,exchange):
  return urllib.request.build_opener(urllib.request.ProxyHandler({}),
   _DeadlineHTTPSHandler(self.context,exchange),_NoRedirect())

def bounded_open_read(opener,request,*,max_body,seconds,cancel_check=None):
 """One absolute HTTPS header/body budget. Only the caller may journal results.

 Production callers supply fixed approved URLs/opener contexts. Synthetic
 openers remain injectable and cannot activate this default HTTPS transport.
 """
 if type(max_body)is not int or not 0<max_body<=1048576 or type(seconds)not in (int,float) or not 0<seconds<=55:
  raise SafeError('Bounded HTTPS transport limits required')
 exchange=_SignerExchange(time.monotonic()+seconds,cancel_check)
 def read_once():
  response=None
  try:
   exchange.check()
   if type(opener)is _PinnedSignerOpener:actual=opener.for_exchange(exchange)
   elif isinstance(opener,urllib.request.OpenerDirector):
    handlers=[h for h in opener.handlers if isinstance(h,urllib.request.HTTPSHandler)]
    if len(handlers)!=1 or request.type!='https':raise SafeError('Approved HTTPS context required')
    actual=urllib.request.build_opener(urllib.request.ProxyHandler({}),
     _DeadlineHTTPSHandler(handlers[0]._context,exchange,request.host),_NoRedirect())
   else:actual=opener
   try:response=actual.open(request,timeout=max(.001,exchange.deadline-time.monotonic()))
   except urllib.error.HTTPError as error:response=error
   exchange.check()
   status=response.code if isinstance(response,urllib.error.HTTPError) else response.status
   exchange.received(status)
   if not isinstance(response,urllib.error.HTTPError) and status!=200:raise TransportEvidenceError('python_http_status')
   if response.headers.get_content_type()!='application/json':raise TransportEvidenceError('python_content_type')
   body=response.read(max_body+1)
   exchange.check()
   if len(body)>max_body:raise TransportEvidenceError('python_response_too_large')
   if isinstance(response,urllib.error.HTTPError):
    # The caller's existing strict error decoder receives only an in-memory
    # bounded body. It never performs another socket read after the deadline.
    raise urllib.error.HTTPError(request.full_url,status,'Local signing refused',response.headers,io.BytesIO(body))
   exchange.result=(status,body)
  except Exception as error:exchange.error=error
  finally:
   if response is not None and hasattr(response,'close'):
    try:response.close()
    except Exception:pass
   exchange.done.set()
 worker=threading.Thread(target=read_once,name='local-signer-bounded-read',daemon=True)
 worker.start()
 while not exchange.done.is_set():
  try:exchange.check()
  except Exception as error:
   exchange.abort();stage,status=exchange.progress()
   raise _SignerReadFailure(error,stage,status) from None
  exchange.done.wait(min(.05,max(0,exchange.deadline-time.monotonic())))
 try:exchange.check()
 except Exception as error:
  exchange.abort();stage,status=exchange.progress()
  raise _SignerReadFailure(error,stage,status) from None
 if exchange.error is not None:
  stage,status=exchange.progress()
  raise _SignerReadFailure(exchange.error,stage,status)
 return exchange.result

def _signer_response(opener,request):
 remaining=_workflow_remaining()
 seconds=_SIGNER_TRANSPORT_SECONDS if remaining is None else min(_SIGNER_TRANSPORT_SECONDS,remaining-_SIGNER_FINAL_JOURNAL_SECONDS)
 if seconds<=0:raise _SignerReadFailure(TimeoutError('Local signing deadline exceeded'),'http_initiated',0)
 return bounded_open_read(opener,request,max_body=65536,seconds=seconds)

class SignerMockExecutor:
 """Trusted fixed-loopback TLS adapter. Only the physically disabled service.
 No environment proxy, redirect, retries, configurable URL or real Fleet path.
 """
 SDK_COMMIT='49977a18fd68567501d59e16a6c9e4a8b9348544'
 def __init__(self,certificate_path,token):
  private_file(certificate_path)
  if not isinstance(token,str) or not 32<=len(token)<=4096 or not token.isascii() or any(c.isspace() for c in token):raise SafeError('Protected local signing capability required')
  self._token=token
  context=ssl.create_default_context(cafile=str(certificate_path))
  context.minimum_version=ssl.TLSVersion.TLSv1_3
  if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:raise SafeError('Verified local signing TLS required')
  self._context=context
  self._opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),_NoRedirect())
 def execute(self,intent,operation_id):
  intent.validated()
  if not isinstance(operation_id,str) or len(operation_id)!=32 or any(c not in '0123456789abcdef' for c in operation_id):raise SafeError('Remote operation invalid')
  raw=canonical({'operation_id':operation_id,'intent':{'version':2,'principal':intent.principal,'target':intent.target,'action':intent.action,'command':intent.command,'payload':intent.payload_json.decode()}})
  request=urllib.request.Request('https://127.0.0.1:8766/simulate',data=raw,headers={'Content-Type':'application/json','Authorization':'Bearer '+self._token},method='POST')
  try:
   with self._opener.open(request,timeout=5) as response:
    if response.status!=200 or response.headers.get_content_type()!='application/json':raise ValueError()
    body=response.read(65537)
   if len(body)>65536:raise ValueError()
   value=json.loads(body,object_pairs_hook=strict_object,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
   expected={'action','simulated','executed','vehicle_execution_verified','execution_enabled','sdk_commit','synthetic_sdk_requests','fleet_network_requests','gross_reserved_microdollars'}
   if not isinstance(value,dict) or set(value)!=expected or value['action']!=intent.action or value['simulated']is not True or any(value[k]is not False for k in ('executed','vehicle_execution_verified','execution_enabled')) or value['sdk_commit']!=self.SDK_COMMIT or type(value['synthetic_sdk_requests'])is not int or not 1<=value['synthetic_sdk_requests']<=2 or any(type(value[k])is not int or value[k]!=0 for k in ('fleet_network_requests','gross_reserved_microdollars')):raise ValueError()
   return value
  except Exception:raise SafeError('Local SDK simulation refused or uncertain; operation consumed; no retry') from None

class SignerLiveExecutor(SignerMockExecutor):
 """TLS-pinned local signer client; live gate is trusted local configuration only."""
 def __init__(self,certificate_path,token,bridge,*,enabled=False):
  if type(enabled)is not bool:raise SafeError('Explicit live signing gate required')
  super().__init__(certificate_path,token)
  self.bridge=bridge;self.execution_enabled=enabled
  self._opener=_PinnedSignerOpener(self._context)
 def _journal(self,method,*args,**kwargs):
  from .storage import journal_deadline
  remaining=_workflow_remaining()
  seconds=_SIGNER_FINAL_JOURNAL_SECONDS if remaining is None else min(remaining,_SIGNER_FINAL_JOURNAL_SECONDS)
  with journal_deadline(seconds):return method(*args,**kwargs)
 def _roundtrip(self,path,operation_id,value):
  from .live_controls import strict_json
  raw=canonical({'operation_id':operation_id,'intent':value})
  request=urllib.request.Request('https://127.0.0.1:8766'+path,data=raw,headers={'Content-Type':'application/json','Authorization':'Bearer '+self._token},method='POST')
  stage='http_initiated';status=0;upstream=None;persistence_failed=False
  try:
   status,body=_signer_response(self._opener,request)
   stage='response_received'
   try:result=strict_json(body)
   except Exception:raise TransportEvidenceError('python_json_invalid') from None
   stage='response_validated'
   if type(result)is dict and 'diagnostic' in result:
    diagnostic=checked_diagnostic(result['diagnostic'])
    try:self._journal(self.bridge.record_response_diagnostic,operation_id,diagnostic)
    except Exception:
     raise SanitizedSigningError(diagnostic).finalization_failed() from None
   return result
  except SanitizedSigningError:raise
  except Exception as error:
   # Only a bounded strict enum payload is extracted; bodies/headers, exception
   # messages and URL/reason values are never retained or exported.
   if isinstance(error,_SignerReadFailure):
    stage,status,error=error.stage,error.status,error.error
   transport_error=error
   if isinstance(error,urllib.error.HTTPError):
    status=error.code if type(error.code)is int and 100<=error.code<=599 else 0
    stage='response_received'
    try:
     if error.headers.get_content_type()!='application/json':raise TransportEvidenceError('python_content_type')
     body=error.read(65537)
     if len(body)>65536:raise TransportEvidenceError('python_response_too_large')
     try:value=strict_json(body)
     except Exception:raise TransportEvidenceError('python_json_invalid') from None
     if type(value)is not dict or set(value)!={'error','diagnostic'} or value['error']!=UPSTREAM_ERROR:raise ValueError()
     upstream=checked_diagnostic(value['diagnostic'])
     try:self._journal(self.bridge.record_response_diagnostic,operation_id,upstream)
     except Exception:persistence_failed=True
    except Exception as parse_error:transport_error=parse_error
   transport=local_transport(transport_error,stage,status)
   try:self._journal(self.bridge.record_local_transport,operation_id,transport)
   except Exception:persistence_failed=True
   if upstream is None:
    try:upstream=self._journal(self.bridge.diagnostics,operation_id)
    except Exception:pass
   if hasattr(error,'close'):
    try:error.close()
    except Exception:pass
   failure=SanitizedSigningError(upstream,transport)
   if persistence_failed:failure.finalization_failed()
   raise failure from None

 def _invalid_receipt(self,operation_id,error):
  transport=local_transport(error,'response_validated',200)
  persistence_failed=False
  try:self._journal(self.bridge.record_local_transport,operation_id,transport)
  except Exception:persistence_failed=True
  diagnostic=None
  try:diagnostic=self._journal(self.bridge.diagnostics,operation_id)
  except Exception:pass
  failure=SanitizedSigningError(diagnostic,transport)
  if persistence_failed:failure.finalization_failed()
  return failure

 def _finish_preserving(self,operation_id,accepted=False,primary=None):
  try:self._journal(self.bridge.finish,operation_id,accepted=accepted)
  except Exception:
   if isinstance(primary,SanitizedSigningError):
    primary.finalization_failed()
    return
   diagnostic=None
   try:diagnostic=self._journal(self.bridge.diagnostics,operation_id)
   except Exception:pass
   failure=SanitizedSigningError(diagnostic).finalization_failed()
   # No primary failure: report the journal stage itself while retaining any
   # known successful HTTP/session milestones. Success cannot escape cleanup.
   failure.diagnostic=checked_diagnostic({**failure.diagnostic,'stage':'operation_failed',
       'failure_stage':'operation_failed','exception_type':'python_journal_error','category':'local'})
   raise failure from None

 @_signer_workflow
 def execute(self,intent,operation_id):
  from .live_controls import wire_intent
  intent.validated()
  if self.execution_enabled is not True:raise SafeError('Live signing disabled; no vehicle request or reservation')
  self._journal(self.bridge.register,operation_id,wire_intent(intent),'execute')
  accepted=False;primary=None
  try:
   value=self._roundtrip('/execute',operation_id,wire_intent(intent))
   expected={'action','simulated','submitted','accepted','vehicle_execution_verified','execution_enabled','sdk_commit','fleet_network_requests','gross_reserved_microdollars'}
   accounting=self._journal(self.bridge.accounting,operation_id)
   command_count=3 if SPECS[intent.action].requires_park else 1 if intent.action=='navigation_send' else 2
   if accounting['grant_consumed']is not True or accounting['phase']!=('state_verified' if SPECS[intent.action].requires_park else 'claimed') or accounting['last_kind']!=('navigation' if intent.action=='navigation_send' else 'command'):raise ValueError()
   if not isinstance(value,dict) or set(value)!=expected or value['action']!=intent.action or value['simulated']is not False or value['submitted']is not True or value['accepted']is not True or value['vehicle_execution_verified']is not False or value['execution_enabled']is not True or value['sdk_commit']!=self.SDK_COMMIT or type(value['fleet_network_requests'])is not int or value['fleet_network_requests']!=command_count or type(value['gross_reserved_microdollars'])is not int or value['gross_reserved_microdollars']!=1000*value['fleet_network_requests'] or value['fleet_network_requests']!=accounting['command_requests'] or accounting['data_requests']!=int(SPECS[intent.action].requires_park or bool(SPECS[intent.action].required_facts)):raise ValueError()
   diagnostic=self._journal(self.bridge.diagnostics,operation_id)
   if diagnostic is not None and (diagnostic['checkpoint_persistence_failed'] or diagnostic['local_finalization_failed']
       or diagnostic['stage']!='operation_succeeded' or diagnostic['failure_stage']!='none'
       or diagnostic['exception_type']!='none' or diagnostic['category']!='none'
       or diagnostic['vehicle_error']!='none'):
    raise SanitizedSigningError(diagnostic)
   accepted=True
   return {**value,'success_evidence':'fleet_reported_success' if intent.action=='navigation_send' else 'vehicle_command_reported_success' if CATALOG[intent.action]['domain']=='SECURITY' else 'vehicle_application_reported_success','resulting_state_verified':False,'prerequisite_data_requests':accounting['data_requests'],'prerequisite_gross_reserved_microdollars':2000*accounting['data_requests'],'total_gross_reserved_microdollars':value['gross_reserved_microdollars']+2000*accounting['data_requests']}
  except SanitizedSigningError as error:primary=error;raise
  except Exception as error:
   primary=self._invalid_receipt(operation_id,error);raise primary from None
  finally:self._finish_preserving(operation_id,accepted,primary)

class SignerPairingVerifier(SignerLiveExecutor):
 """Trusted operator-only nonphysical diagnostic; never exposed as an MCP tool."""
 def __init__(self,certificate_path,token,bridge,*,enabled=False):
  super().__init__(certificate_path,token,bridge,enabled=False)
  if type(enabled)is not bool:raise SafeError('Explicit pairing diagnostic gate required')
  self.diagnostic_enabled=enabled
 @_signer_workflow
 def verify(self):
  if self.diagnostic_enabled is not True:raise SafeError('Pairing diagnostic disabled; no vehicle request or reservation')
  operation=secrets.token_hex(16)
  value={'version':1,'principal':self.bridge.owner,'target':self.bridge.target,'action':'verify_pairing'}
  self._journal(self.bridge.register,operation,value,'verify_pairing')
  primary=None
  try:
   result=self._roundtrip('/verify_pairing',operation,value)
   expected={'pairing_verified','execution_enabled','vehicle_execution_verified','sdk_commit','fleet_network_requests','gross_reserved_microdollars'}
   accounting=self._journal(self.bridge.accounting,operation)
   if not isinstance(result,dict) or set(result)!=expected or result['pairing_verified']is not True or result['execution_enabled']is not False or result['vehicle_execution_verified']is not False or result['sdk_commit']!=self.SDK_COMMIT or type(result['fleet_network_requests'])is not int or result['fleet_network_requests']!=accounting['command_requests'] or type(result['gross_reserved_microdollars'])is not int or result['gross_reserved_microdollars']!=1000*result['fleet_network_requests'] or not accounting['pairing_stored']:raise ValueError()
   diagnostic=self._journal(self.bridge.diagnostics,operation)
   if diagnostic is not None and (diagnostic['checkpoint_persistence_failed'] or diagnostic['local_finalization_failed']
       or diagnostic['stage']!='operation_succeeded' or diagnostic['failure_stage']!='none'
       or diagnostic['exception_type']!='none' or diagnostic['category']!='none'
       or diagnostic['vehicle_error']!='none'):
    raise SanitizedSigningError(diagnostic)
   return {**result,'prerequisite_data_requests':accounting['data_requests'],'prerequisite_gross_reserved_microdollars':2000*accounting['data_requests'],'total_gross_reserved_microdollars':result['gross_reserved_microdollars']+2000*accounting['data_requests']}
  except SanitizedSigningError as error:primary=error;raise
  except Exception as error:
   primary=self._invalid_receipt(operation,error);raise primary from None
  finally:self._finish_preserving(operation,primary=primary)

class SignerInfotainmentVerifier(SignerLiveExecutor):
 """Owner-local, one-use fresh INFOTAINMENT handshake only. No physical payload."""
 def __init__(self,certificate_path,token,bridge,*,enabled=False):
  super().__init__(certificate_path,token,bridge,enabled=False)
  if type(enabled)is not bool:raise SafeError('Explicit infotainment diagnostic gate required')
  self.diagnostic_enabled=enabled
 @_signer_workflow
 def verify(self):
  return self._verify(secrets.token_hex(16))
 @_signer_workflow
 def verify_authorized(self,operation_id):
  """Trusted-local additional authority; never available through remote tools."""
  return self._verify(operation_id,require_additional=True)
 @_signer_workflow
 def _verify(self,operation,*,require_additional=False):
  if self.diagnostic_enabled is not True or self.bridge.execution_enabled or self.bridge.pairing_diagnostic_enabled:
   raise SafeError('Infotainment diagnostic disabled; no vehicle request or reservation')
  value={'version':1,'principal':self.bridge.owner,'target':self.bridge.target,'action':'verify_infotainment'}
  if require_additional:
   self._journal(self.bridge.register,operation,value,'verify_infotainment',require_additional_infotainment=True)
  else:self._journal(self.bridge.register,operation,value,'verify_infotainment')
  primary=None
  try:
   result=self._roundtrip('/verify_infotainment',operation,value)
   expected={'infotainment_verified','execution_enabled','vehicle_execution_verified','sdk_commit',
             'fleet_network_requests','gross_reserved_microdollars','diagnostic'}
   accounting=self._journal(self.bridge.accounting,operation)
   if (type(result)is not dict or set(result)!=expected or result['infotainment_verified']is not True
       or result['execution_enabled']is not False or result['vehicle_execution_verified']is not False
       or result['sdk_commit']!=self.SDK_COMMIT or type(result['fleet_network_requests'])is not int
       or result['fleet_network_requests']!=1 or type(result['gross_reserved_microdollars'])is not int
       or result['gross_reserved_microdollars']!=1000 or accounting['command_requests']!=1
       or accounting['data_requests']!=0 or accounting['last_kind']!='handshake'
       or accounting['phase']!='claimed' or accounting['pairing_stored']is not False
       or accounting['grant_consumed']is not False):raise ValueError()
   evidence=checked_diagnostic(result['diagnostic'])
   if evidence['checkpoint_persistence_failed'] or evidence['local_finalization_failed']:
    raise SanitizedSigningError(evidence)
   if (evidence['stage']!='operation_succeeded' or evidence['kind']!='handshake'
       or evidence['failure_stage']!='none' or evidence['exception_type']!='none'
       or evidence['category']!='none' or evidence['vehicle_error']!='none'
       or evidence['http_status']!=200 or not all(evidence[k] for k in
          ('reservation_acknowledged','http_initiated','request_written',
           'response_received','authenticated_session_ready'))):
    raise ValueError()
   return {**result,'diagnostic':evidence,'physical_execution':False,'pairing_proof_changed':False,
           'prerequisite_data_requests':0,'total_gross_reserved_microdollars':1000}
  except SanitizedSigningError as error:primary=error;raise
  except Exception as error:
   primary=self._invalid_receipt(operation,error);raise primary from None
  finally:self._finish_preserving(operation,primary=primary)

class RemoteOperations:
 def __init__(self,owner,target,*,executor=None,clock=time.monotonic):
  if executor is not None and type(executor)not in (MockRemoteExecutor,SignerMockExecutor,SignerLiveExecutor):raise SafeError('Live remote controls not enabled')
  self.owner=owner;self.target=target;self.executor=executor;self.clock=clock;self.pending={};self.lock=threading.RLock();self.remote_owner_approval_enabled=False;self.browser_approved=set()
 def owner_check(self,identity):
  if type(identity)is not VerifiedIdentity or identity.user_id!=self.owner:raise SafeError('Verified remote owner required')
 def prepare(self,identity,action,parameters):
  self.owner_check(identity)
  if self.remote_owner_approval_enabled:
   # Remote review precedes grant creation. Navigation's fresh timestamp is
   # bound in this proposal and retained unchanged in its later exact grant.
   intent=ControlIntent.build(self.owner,self.target,action,parameters)
  elif type(self.executor)is SignerLiveExecutor and self.executor.execution_enabled is True and hasattr(self.executor,'bridge'):
   intent=self.executor.bridge.grants.prepare_intent(action,parameters)
  else:intent=ControlIntent.build(self.owner,self.target,action,parameters)
  now=self.clock()
  with self.lock:
   self.pending={k:v for k,v in self.pending.items() if 0<=now-v[1]<300}
   if len(self.pending)>=32:raise SafeError('Remote proposal capacity reached')
   operation=secrets.token_hex(16);self.pending[operation]=(intent,now,intent.binding())
  preview=intent.preview();preview.pop('estimated_gross_reservation_microdollars',None)
  if type(self.executor)is SignerLiveExecutor and self.executor.execution_enabled is True:
   security=action in ('lock','unlock','front_trunk','rear_trunk')
   preview['execution_enabled']=True
   return {'operation_id':operation,'expires_in_seconds':300,**preview,'simulated':False,'gross_reserved_microdollars':0,'estimated_gross_reservation_microdollars':ceiling(action)}
  return {'operation_id':operation,'expires_in_seconds':300,**preview,'simulated':True,'gross_reserved_microdollars':0}
 def browser_review(self,operation_id):
  if not self.remote_owner_approval_enabled or not isinstance(self.executor,SignerLiveExecutor) or not self.executor.execution_enabled:raise SafeError('Remote owner approval disabled')
  with self.lock:
   intent,issued,binding=self.pending.get(operation_id,(None,0,None))
   if intent is None or not 0<=self.clock()-issued<300 or operation_id in self.browser_approved:raise SafeError('Proposal expired or already approved')
   data=json.loads(intent.payload_json)
   if intent.action=='navigation_send':data={'destination':data['value']['android.intent.TEXT']}
   return {'operation_id':operation_id,'action':intent.action,'effect':SPECS[intent.action].effect,'parameters':data,'maximum_gross_microdollars':ceiling(intent.action),'motorized_port_confirmation_required':intent.action=='charge_port_close'}
 def browser_approve(self,operation_id,*,motorized_port_confirmed=False):
  # Invoked only by the gateway-only, non-MCP human browser route. No public
  # tool, model argument or mere authenticated MCP call can arm this grant.
  with self.lock:
   review=self.browser_review(operation_id)
   intent,issued,binding=self.pending[operation_id]
   if intent.binding()!=binding or type(motorized_port_confirmed)is not bool:raise SafeError('Exact owner review refused')
   if intent.action=='charge_port_close':
    if not motorized_port_confirmed:raise SafeError('Owner motorized-port confirmation required')
    bridge=self.executor.bridge
    with bridge.store.transaction() as db:
     db.execute('CREATE TABLE IF NOT EXISTS trusted_vehicle_hardware(owner_hash TEXT,target_hash TEXT,key_sha256 TEXT,motorized_port INTEGER NOT NULL CHECK(motorized_port=1),PRIMARY KEY(owner_hash,target_hash,key_sha256))')
     db.execute('INSERT OR IGNORE INTO trusted_vehicle_hardware VALUES(?,?,?,1)',(bridge.budget.owner,digest(self.target),bridge.key))
   grant=self.executor.bridge.grants.arm(intent,ceiling(intent.action),ttl_seconds=min(120,300-(self.clock()-issued)))
   self.browser_approved.add(operation_id)
   return {'approved':True,'operation_id':operation_id,'action':intent.action,'gross_ceiling_microdollars':ceiling(intent.action),'one_use':True,'vehicle_requests':0}
 def execute(self,identity,operation_id,*,expected_control_mode):
  self.owner_check(identity)
  mode='live' if type(self.executor)is SignerLiveExecutor and self.executor.execution_enabled is True else 'mock'
  if expected_control_mode not in ('mock','live') or expected_control_mode!=mode:raise SafeError('Control mode mismatch; proposal untouched; no request or spending')
  if not isinstance(operation_id,str) or len(operation_id)!=32 or any(c not in '0123456789abcdef' for c in operation_id):raise SafeError('Remote operation invalid')
  with self.lock:
   if self.remote_owner_approval_enabled and operation_id not in self.browser_approved:raise SafeError('Exact human-browser approval required; proposal untouched')
   intent,issued,binding=self.pending.pop(operation_id,(None,0,None))
  if self.remote_owner_approval_enabled and operation_id not in self.browser_approved:raise SafeError('Exact human-browser approval required; no vehicle request')
  self.browser_approved.discard(operation_id)
  if intent is None or not 0<=self.clock()-issued<300 or intent.binding()!=binding:raise SafeError('Remote operation expired, consumed or changed')
  if self.executor is None:raise SafeError('Live remote controls disabled; operation consumed; no car request or spending')
  return self.executor.execute(intent,operation_id)
class RemoteMockMCP(MockHTTPMCP):
 """Optional synthetic integration; existing live launcher never selects it."""
 def __init__(self,owner_id,operations,*,service=None,allow_live_reads=False):
  super().__init__(owner_id,service=service,allow_live_reads=allow_live_reads)
  if type(operations)is not RemoteOperations or operations.owner!=owner_id:raise SafeError('Remote owner configuration refused')
  self.operations=operations
 def post(self,path,raw,identity=None):
  if path!='/mcp':return 404,{}
  if type(identity)is not VerifiedIdentity or not identity.user_id:return 401,{}
  if identity.user_id!=self.owner_id:return 403,{}
  if not isinstance(raw,bytes) or len(raw)>65536:return 413,{}
  try:message=json.loads(raw,object_pairs_hook=strict_object,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
  except Exception:return 400,{}
  if not isinstance(message,dict) or message.get('jsonrpc')!='2.0' or not isinstance(message.get('method'),str) or ('id' in message and type(message.get('id'))not in (str,int)):return 400,{}
  if 'id' not in message:return super().post(path,raw,identity)
  if message.get('method')=='tools/list':
   live=type(self.operations.executor)is SignerLiveExecutor and self.operations.executor.execution_enabled is True
   return 200,{'jsonrpc':'2.0','id':message['id'],'result':{'tools':TOOLS+(LIVE_REMOTE_TOOLS if live else REMOTE_TOOLS)}}
  params=message.get('params',{})
  if not isinstance(params,dict):return 400,{}
  if message.get('method')!='tools/call' or params.get('name')not in {t['name'] for t in REMOTE_TOOLS}:return super().post(path,raw,identity)
  try:
   if set(params)-{'name','arguments','_meta'}:raise SafeError('Remote parameters refused')
   args=params.get('arguments',{})
   if params['name'].startswith('prepare_') and params['name']!='prepare_control':
    action=params['name'][8:];typed_parameters(action,args);out=self.operations.prepare(identity,action,args)
   elif params['name']=='prepare_control':arguments(args,('action','parameters'));out=self.operations.prepare(identity,args['action'],args['parameters'])
   else:arguments(args,('operation_id','expected_control_mode'));out=self.operations.execute(identity,args['operation_id'],expected_control_mode=args['expected_control_mode'])
   result={'content':[{'type':'text','text':json.dumps(out,allow_nan=False)}],'isError':False}
  except SanitizedSigningError as e:result={'content':[{'type':'text','text':str(e)}],'isError':True,'structuredContent':e.public_fields()}
  except SafeError as e:result={'content':[{'type':'text','text':str(e)}],'isError':True}
  except Exception:result={'content':[{'type':'text','text':'Remote operation failed; private details withheld'}],'isError':True}
  return 200,{'jsonrpc':'2.0','id':message['id'],'result':result}
