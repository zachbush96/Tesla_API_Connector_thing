"""Reviewed fixed-origin OAuth POST adapter; disabled unless explicitly approved."""
import json
import urllib.parse
import urllib.request
import urllib.error
from .oauth import TOKEN_URL, REDIRECT
from .service import SafeError, NoRedirect
from .audit import strict_object
import hashlib

class TLSOAuthTransport:
    def __init__(self,*,approved=False,opener=None,audit=None):
        self.audit=audit or (lambda *_:None)
        self.approved=approved
        self.opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def exchange(self,url,form):
        if not self.approved:raise SafeError('OAuth network transport disabled')
        if url!=TOKEN_URL or not isinstance(form,dict) or set(form)-{'grant_type','client_id','client_secret','code','audience','redirect_uri','refresh_token','scope'}:
            raise SafeError('OAuth target or form refused')
        expected = ({'grant_type','client_id','refresh_token'} if form.get('grant_type')=='refresh_token'
                    else {'grant_type','client_id','client_secret','code','audience','redirect_uri'})
        if set(form)-{'scope'}!=expected or form.get('grant_type') not in ('authorization_code','refresh_token') or any(not isinstance(v,str) or not v or len(v)>16000 or any(ord(c)<33 or ord(c)>126 for c in v) for k,v in form.items() if k!='scope'):
            raise SafeError('OAuth form refused')
        if 'scope' in form:
            from .oauth import ALLOWED_SCOPES
            scope=form['scope']
            if form['grant_type']!='authorization_code' or not isinstance(scope,str) or scope!=' '.join(sorted(set(scope.split()))) or not set(scope.split())<=ALLOWED_SCOPES or 'openid' not in scope.split():
                raise SafeError('OAuth scope form refused')
        if form['grant_type']=='authorization_code' and (form['redirect_uri']!=REDIRECT or form['audience'] not in {
                'https://fleet-api.prd.na.vn.cloud.tesla.com','https://fleet-api.prd.eu.vn.cloud.tesla.com','https://fleet-api.prd.cn.vn.cloud.tesla.cn'}):
            raise SafeError('OAuth audience or redirect refused')
        try:
            encoded=urllib.parse.urlencode(form).encode()
            if len(encoded)>50000:raise SafeError('OAuth request too large')
            request=urllib.request.Request(TOKEN_URL,data=encoded,method='POST',headers={
                'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})
            with self.opener.open(request,timeout=10) as response:
                raw=response.read(65537)
                status=getattr(response,'status',None)
                headers=getattr(response,'headers',{})
                content_type=headers.get('Content-Type','')
                txid=headers.get('x-txid')
                metadata={'scope_sent':'scope' in form,'response_bytes':len(raw),'content_type_json':isinstance(content_type,str) and content_type.split(';')[0].strip().lower()=='application/json'}
                if type(status)is int:metadata['http_status']=status
                if isinstance(txid,str):metadata['x_txid_sha256']=hashlib.sha256(txid.encode()).hexdigest()
                self.audit('exchange-http',metadata)
                if len(raw)>65536:raise SafeError('OAuth response too large')
                result=json.loads(raw,object_pairs_hook=strict_object,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                if not isinstance(result,dict):raise SafeError('Invalid OAuth response')
                self.audit('exchange-json',{'cause':'none'})
                return result
        except urllib.error.HTTPError as error:
            self.audit('exchange-http',{'http_status':error.code,'cause':'http'});error.close();raise SafeError('OAuth exchange refused') from None
        except Exception as error:
            self.audit('exchange-json',{'cause':'duplicate-field' if isinstance(error,ValueError) and str(error)=='duplicate-field' else 'json' if isinstance(error,ValueError) else 'network'})
            raise SafeError('OAuth exchange failed; details withheld') from None
