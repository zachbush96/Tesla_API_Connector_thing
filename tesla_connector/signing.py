"""Reviewed fixed-loopback signing proxy contract; public transport DISABLED.

No constructor starts a service or reads signing/OAuth credentials. A later
activation review must replace the disabled send gate and enforce proxy-internal
no-retry/all-network-attempt accounting before using this contract in production.
"""
import json
import re
import ssl
import urllib.error
import urllib.request
from .audit import strict_object
from .controls import ControlIntent,SPECS
from .service import SafeError,NoRedirect,private_file

MAX_BODY=16384
MAX_RESPONSE=65536


def checked_request(request):
    if not isinstance(request,urllib.request.Request) or request.get_method()!='POST':raise SafeError('Signing request refused')
    match=re.fullmatch(r'https://localhost:4443/api/1/vehicles/([A-HJ-NPR-Z0-9]{17})/command/([a-z_]+)',request.full_url)
    if not match or not isinstance(request.data,bytes) or not 1<=len(request.data)<=MAX_BODY:raise SafeError('Signing request refused')
    headers={k.lower():v for k,v in request.header_items()}
    if set(headers)-{'authorization','content-type','accept'} or headers.get('content-type')!='application/json':raise SafeError('Signing headers refused')
    bearer=headers.get('authorization','')
    if not isinstance(bearer,str) or not bearer.startswith('Bearer ') or not 1<=len(bearer[7:])<=16000 or any(ord(c)<33 or ord(c)>126 for c in bearer[7:]):raise SafeError('Signing authorization refused')
    try:
        data=json.loads(request.data,object_pairs_hook=strict_object)
        command=match[2]
        actions=[name for name,spec in SPECS.items() if spec.endpoint==command]
        if command=='actuate_trunk':actions=['front_trunk' if data.get('which_trunk')=='front' else 'rear_trunk']
        if len(actions)!=1:raise ValueError()
        ControlIntent('trusted-signing-owner',match[1],actions[0],command,request.data).validated()
    except Exception:raise SafeError('Signing command contract refused') from None
    return request


def verified_tls_opener(certificate_path):
    # Trusted local certificate is read only after separate TLS/service approval.
    certificate=private_file(certificate_path)
    if len(certificate)>65536 or "PRIVATE KEY" in certificate:raise SafeError('Public trusted certificate required')
    context=ssl.create_default_context(cafile=str(certificate_path))
    if context.verify_mode!=ssl.CERT_REQUIRED or not context.check_hostname:raise SafeError('Verified proxy TLS required')
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())


def _bounded_roundtrip(request,opener):
    """Private implementation tested only with explicit synthetic openers."""
    checked_request(request)
    try:
        with opener.open(request,timeout=10) as response:
            if getattr(response,'status',None)!=200 or response.headers.get('Content-Type','').split(';')[0].strip().lower()!='application/json':raise SafeError('Signing response refused; approval must not be reused')
            raw=response.read(MAX_RESPONSE+1)
            if len(raw)>MAX_RESPONSE:raise ValueError()
            body=json.loads(raw,object_pairs_hook=strict_object,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            result=body['response']['result']
            if type(result)is not bool:raise ValueError()
            # Never propagate arbitrary reason/error/details/path/identifier.
            return {'response':{'result':result}}
    except urllib.error.HTTPError as error:
        category={401:'authorization-rejected',403:'permission-rejected',408:'vehicle-asleep-or-offline',412:'virtual-key-not-paired',429:'rate-limited'}.get(error.code,'proxy-rejected')
        error.close();raise SafeError('Signing '+category+'; no wake or retry') from None
    except Exception:
        raise SafeError('Signing outcome unconfirmed; no wake or retry; approval must not be reused') from None


class DisabledSignedProxyTransport:
    simulated=False
    execution_enabled=False
    def send(self,request):
        checked_request(request)
        raise SafeError('Signing service activation not approved; no network attempted')
