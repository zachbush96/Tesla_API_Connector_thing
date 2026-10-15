"""Loopback mock broker. Human and MCP credentials are separate; no live transports."""
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from .callback import CallbackBoundary, BrowserIdentity
from .http_mock import MockHTTPMCP, VerifiedIdentity
from .oauth import REDIRECT
from .service import SafeError

from .settings import PUBLIC_ORIGIN
ORIGIN = PUBLIC_ORIGIN

class Broker:
    def __init__(self, owner, operator_token, mcp_token, oauth=None, clock=time.monotonic, local_host='127.0.0.1:8765', gateway_token=None, *, service=None, allow_live_reads=False, control_workflow=None,remote_operations=None,signer_bridge=None,signer_bridge_token=None):
        for token in (operator_token, mcp_token):
            if not isinstance(token, str) or len(token) < 32 or len(token) > 4096 or not token.isascii() or any(c.isspace() for c in token):
                raise SafeError('Separate protected broker credentials required')
        if hmac.compare_digest(operator_token, mcp_token):
            raise SafeError('Operator and MCP credentials must differ')
        self.owner = owner
        self.local_host = local_host
        self.operator_hash = hashlib.sha256(operator_token.encode()).digest()
        self.mcp_hash = hashlib.sha256(mcp_token.encode()).digest()
        self.gateway_hash = None
        self.signer_bridge = signer_bridge
        self.signer_bridge_hash = None
        if signer_bridge is not None:
            from .live_controls import SignerBridge
            if type(signer_bridge) is not SignerBridge or signer_bridge.owner != owner or not isinstance(signer_bridge_token,str) or len(signer_bridge_token)!=64 or any(c not in '0123456789abcdef' for c in signer_bridge_token) or signer_bridge_token in (operator_token,mcp_token,gateway_token):
                raise SafeError('Distinct protected internal signer capability required')
            self.signer_bridge_hash=hashlib.sha256(signer_bridge_token.encode()).digest()
        elif signer_bridge_token is not None:
            raise SafeError('Internal signer bridge configuration incomplete')
        if gateway_token is not None:
            if not isinstance(gateway_token,str) or not 32<=len(gateway_token)<=4096 or not gateway_token.isascii() or any(c.isspace() for c in gateway_token) or gateway_token in (operator_token,mcp_token):
                raise SafeError('Distinct protected gateway capability required')
            self.gateway_hash=hashlib.sha256(gateway_token.encode()).digest()
        if control_workflow is not None and control_workflow.owner != owner:
            raise SafeError('Control workflow belongs to another owner')
        self.control_workflow = control_workflow
        self.oauth, self.clock = oauth, clock
        self.sessions = {}
        self.session_lock = threading.RLock()
        if remote_operations is None:
            self.mcp = MockHTTPMCP(owner, service=service, allow_live_reads=allow_live_reads)
        else:
            from .remote_controls import RemoteMockMCP
            self.mcp = RemoteMockMCP(owner,remote_operations,service=service,allow_live_reads=allow_live_reads)

    def authenticated(self, headers, expected):
        value = headers.get('authorization', '')
        if not value.startswith('Bearer ') or len(value) > 4103:
            return False
        return hmac.compare_digest(hashlib.sha256(value[7:].encode()).digest(), expected)

    def handle(self, method, target, headers, body=b'', *, request_cancelled=None):
        privacy = {'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
                   'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'", 'X-Content-Type-Options':'nosniff'}
        def response(status, data, extra=None):
            return status, {**privacy, **(extra or {})}, data
        if headers.get('host') not in (urllib.parse.urlsplit(ORIGIN).netloc,self.local_host):
            return response(400, {'error':'Host refused'})
        if not isinstance(target, str) or len(target)>8192 or not target.startswith('/') or target.startswith('//'):
            return response(400, {'error':'Target refused'})
        path = urllib.parse.urlsplit(target).path
        if headers.get('origin') is not None and headers['origin'] != ORIGIN:
            return response(403, {'error':'Origin refused'})
        if len(body)>65536:
            return response(413, {'error':'Body too large'})
        if path.startswith('/internal/signer/'):
            if self.signer_bridge is None or self.signer_bridge_hash is None or headers.get('host') != self.local_host or method != 'POST' or target != path or headers.get('origin') is not None or headers.get('cookie') is not None or not self.authenticated(headers,self.signer_bridge_hash):
                return response(403, {'error':'Protected signing operation refused; no retry; private details withheld'})
            if headers.get('content-type','').split(';')[0].strip().lower() != 'application/json':
                return response(415,{})
            # Trusted fixed-loopback callbacks have an absolute caller cutoff.
            # A supplied header can only shorten the local fixed ceiling.
            from .storage import journal_deadline
            limit = 25.0 if path == '/internal/signer/claim' else 0.75
            value = headers.get('x-connector-signer-deadline-ms')
            try:
                if value is not None:
                    if not isinstance(value,str) or not value.isascii() or not value.isdecimal() or len(value)>16:
                        raise ValueError()
                    limit = min(limit,int(value)/1000-time.time())
                if limit <= 0:
                    raise ValueError()
                with journal_deadline(limit,cancelled=request_cancelled):
                    status,data=self.signer_bridge.handle(path,body)
            except Exception:
                return response(409, {'error':'Protected signing operation refused; no retry; private details withheld'})
            return response(status,data)
        if path == '/health':
            if method != 'GET' or not self.authenticated(headers,self.mcp_hash):
                return response(401, {}, {'WWW-Authenticate':'Bearer'})
            live=self.signer_bridge is not None and self.signer_bridge.execution_enabled is True
            data = {'status':'ready', 'mode':self.mcp.service.config.mode, 'oauth_enabled':self.oauth is not None, 'vehicle_commands_enabled':bool(live)}
            if self.signer_bridge is not None or self.mcp.service.config.mode=='live-read':
                from . import storage
                from .execution_grants import OneActionGrants
                # Safe class import only: disabled health creates no store,
                # grant, authorization or reconciliation schema/record.
                data['reconciliation_code_loaded'] = all(callable(getattr(OneActionGrants,name,None)) for name in ('plan_reconciliation','authorize_reconciliation','reconcile'))
                data['deadline_policy_loaded'] = getattr(storage,'DEADLINE_POLICY_VERSION',None)==1
            return response(200,data)
        if path == '/mcp':
            if not self.authenticated(headers,self.mcp_hash) and (self.gateway_hash is None or not self.authenticated(headers,self.gateway_hash)):
                return response(401, {}, {'WWW-Authenticate':'Bearer'})
            if method!='POST':
                return response(405, {}, {'Allow':'POST'})
            if headers.get('content-type','').split(';')[0].strip().lower()!='application/json':
                return response(415,{})
            # Trusted human-browser methods exist only on the dedicated Site
            # gateway capability; they are absent from the public MCP catalog.
            try:
                from .audit import strict_object
                message=json.loads(body,object_pairs_hook=strict_object)
                if message.get('method')in ('owner/control/review','owner/control/approve'):
                    if self.gateway_hash is None or not self.authenticated(headers,self.gateway_hash) or set(message)!={'jsonrpc','id','method','params'} or message['jsonrpc']!='2.0':raise ValueError()
                    ops=self.mcp.operations;args=message['params']
                    if type(args)is not dict:raise ValueError()
                    if message['method']=='owner/control/review' and set(args)=={'operation_id'}:result=ops.browser_review(args['operation_id'])
                    elif message['method']=='owner/control/approve' and set(args)=={'operation_id','motorized_port_confirmed'}:result=ops.browser_approve(args['operation_id'],motorized_port_confirmed=args['motorized_port_confirmed'])
                    else:raise ValueError()
                    return response(200,{'jsonrpc':'2.0','id':message['id'],'result':result})
            except Exception:
                return response(403,{'error':'Human owner approval refused; no vehicle request'})
            status,data=self.mcp.post(path,body,VerifiedIdentity(self.owner))
            return response(status,data)
        if path=='/operator/session' and method=='POST':
            if not self.authenticated(headers,self.operator_hash) or headers.get('origin')!=ORIGIN or body:
                return response(403, {'error':'Owner session refused'})
            with self.session_lock:
                now=self.clock()
                self.sessions={k:v for k,v in self.sessions.items() if now<v[2]}
                if len(self.sessions)>=8:
                    return response(429, {'error':'Session capacity reached'})
                session,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
                self.sessions[session]=(self.owner,csrf,now+300)
            return response(200,{'csrf':csrf}, {'Set-Cookie':f'__Host-connector={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300'})
        try:
            cookie=SimpleCookie();cookie.load(headers.get('cookie',''))
            session=cookie['__Host-connector'].value
            with self.session_lock:row=self.sessions.get(session)
            if not row or self.clock()>=row[2]:raise ValueError()
        except Exception:
            return response(401, {'error':'Owner browser session required'})
        identity=BrowserIdentity(row[0],session)
        if path.startswith('/operator/control/'):
            if method != 'POST' or headers.get('origin') != ORIGIN or not hmac.compare_digest(headers.get('x-csrf-token',''),row[1]):
                return response(403, {'error':'Owner control confirmation refused'})
            if self.control_workflow is None:
                return response(503, {'error':'Owner control review not configured; execution disabled'})
            if headers.get('content-type','').split(';')[0].strip().lower() != 'application/json':
                return response(415,{})
            try:
                from .audit import strict_object
                data=json.loads(body,object_pairs_hook=strict_object)
                if not isinstance(data,dict):raise ValueError()
                if path=='/operator/control/prepare' and set(data)=={'action','arguments'}:
                    reference,preview=self.control_workflow.prepare(data['action'],data['arguments'])
                    return response(200, {'intent_id':reference,'preview':preview})
                if path=='/operator/control/review' and set(data)=={'intent_id'}:
                    reference=data['intent_id']
                    review=self.control_workflow.owner_review(reference)
                    binding=self.control_workflow.pending[reference][0].binding().hex()
                    return response(200, {'review':review,'review_sha256':binding})
                if path=='/operator/control/approve' and set(data)=={'intent_id','review_sha256'}:
                    binding=data['review_sha256']
                    if not isinstance(binding,str) or len(binding)!=64:raise ValueError()
                    intent,ticket=self.control_workflow.confirm(data['intent_id'],bytes.fromhex(binding),owner=row[0])
                    return response(200, {'approval_ticket':ticket,'command':intent.command,'execution_enabled':False,'executed':False})
                # Deliberately no execute/submit route, even with an owner ticket.
                return response(404,{})
            except Exception:
                return response(400, {'error':'Owner control request refused; private details withheld'})
        if path=='/oauth/start' and method=='POST':
            if headers.get('origin')!=ORIGIN or not hmac.compare_digest(headers.get('x-csrf-token',''),row[1]) or body:
                return response(403, {'error':'CSRF check failed'})
            if self.oauth is None:return response(503, {'error':'OAuth disabled'})
            try:url=self.oauth.begin(session) # Minimal read scopes only; no offline grant.
            except Exception:return response(400, {'error':'Authorization unavailable'})
            return response(303, {}, {'Location':url})
        if path=='/oauth/callback':
            if self.oauth is None:return response(503, {'error':'OAuth disabled'})
            return CallbackBoundary(self.oauth,self.owner).handle(method,ORIGIN+target,identity)
        if path=='/setup/complete' and method=='GET':
            return response(200, {'status':'Callback completed; no vehicle operation performed'})
        return response(404,{})
