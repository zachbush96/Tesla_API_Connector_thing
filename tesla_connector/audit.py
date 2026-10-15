"""Strict-schema credential-free setup audit; no arbitrary strings or exception dumps."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from .service import SafeError

STAGES={'runtime','authorize','callback','exchange-http','exchange-json','token-fields','identity-header','identity-keys','identity-result','vault','setup-result'}
HEX=re.compile(r'[a-f0-9]{64}')
VERSION=re.compile(r'[0-9]+(?:\.[0-9]+){1,3}')
FLAGS={'nonce_requested','callback_issuer_matches','scope_sent','scope_present','id_token_present','access_token_present','refresh_token_present','id_access_identical','content_type_json','kid_has_outer_whitespace','kid_ascii','verified','stored','vehicle_read_performed','vin_config_valid'}
COUNTS={'http_status','response_bytes','key_count','matching_key_count','kid_length','python_major','python_minor'}
HASHES={'client_id_sha256','audience_sha256','token_key_sha256','trimmed_key_sha256','x_txid_sha256'}
TAGS={'missing_claim':{'exp','iat','iss','aud','sub','nonce'},'identity_profile':{'thirdparty-pinned','unexpected'},'region':{'na','eu','cn'},'algorithm':{'RS256','other','missing'},'token_field':{'id_token','access_token'},'cause':{'none','network','http','json','duplicate-field','dependency','token-format','algorithm','key-fetch','key-document','key-selection','key-not-published','key-ambiguous','key-unusable','signature','issuer','audience','expiry','issued-time','required-claim','claims','nonce','unexpected'},'bearer_type':{'bearer','other','missing'}}

def filtered(values):
    result={}
    if not isinstance(values,dict):return result
    for key,value in values.items():
        if key in FLAGS and type(value)is bool:result[key]=value
        elif key in COUNTS and type(value)is int and 0<=value<=1000000:result[key]=value
        elif key in HASHES and isinstance(value,str) and HEX.fullmatch(value):result[key]=value
        elif key in TAGS and isinstance(value,str) and value in TAGS[key]:result[key]=value
        elif key=='published_key_sha256' and isinstance(value,list) and len(value)<=64 and all(isinstance(v,str) and HEX.fullmatch(v) for v in value):result[key]=value
        elif key in ('pyjwt_version','cryptography_version') and isinstance(value,str) and VERSION.fullmatch(value):result[key]=value
        elif key=='source_sha256' and isinstance(value,dict):
            names={'run_live_broker.py','oauth.py','oauth_transport.py','oidc.py','runtime.py','audit.py','setup_loop.py'}
            result[key]={k:v for k,v in value.items() if k in names and isinstance(v,str) and HEX.fullmatch(v)}
    return result

class SetupAudit:
    def __init__(self,path):
        self.path=Path(path);self.correlation_id=secrets.token_hex(16)
    def __call__(self,stage,values=None):
        if stage not in STAGES:return
        record={'correlation_id':self.correlation_id,'stage':stage,'unix_time':int(time.time()),'data':filtered(values)}
        fd=None
        try:
            fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
            with os.fdopen(fd,'w') as out:
                fd=None # The stream now owns the descriptor, including validation failures.
                info=os.fstat(out.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
                    raise SafeError('Setup audit must be an owner-only regular file owned by this user')
                out.write(json.dumps(record,allow_nan=False)+'\n');out.flush();os.fsync(out.fileno())
        except OSError:
            raise SafeError('Cannot append protected setup audit') from None
        finally:
            if fd is not None:os.close(fd)

def runtime_metadata(base):
    import sys
    files={'run_live_broker.py':base/'run_live_broker.py',**{name:base/'tesla_connector'/name for name in ['oauth.py','oauth_transport.py','oidc.py','runtime.py','audit.py','setup_loop.py']}}
    from .oidc import ISSUER,JWKS
    profile='thirdparty-pinned' if ISSUER=='https://auth.tesla.com/oauth2/v3/nts' and JWKS=='https://auth.tesla.com/oauth2/v3/discovery/thirdparty/keys' else 'unexpected'
    result={'identity_profile':profile,'python_major':sys.version_info.major,'python_minor':sys.version_info.minor,'source_sha256':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}}
    for package,key in [('PyJWT','pyjwt_version'),('cryptography','cryptography_version')]:
        try:result[key]=importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:pass
    return result

def strict_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate-field')
        result[key]=value
    return result
