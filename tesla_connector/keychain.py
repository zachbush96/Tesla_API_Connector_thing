"""Protected macOS credential backend. No logging, CLI export or automatic reads."""
import ctypes as C
import json
import re
from .service import SafeError


def credentials(values):
    if not isinstance(values,dict) or set(values)!={'client_id','client_secret'}:
        raise SafeError('Tesla client credentials unavailable')
    for value in values.values():
        if not isinstance(value,str) or not value or len(value)>8000 or not value.isascii() or any(c.isspace() for c in value):
            raise SafeError('Invalid local credential entry')
    return values


class MacKeychain:
    """Service-scoped, local-device, unlocked-only generic password records."""
    def operation(self, account, payload=None, add_only=False):
        if account!='tesla-client' and not re.fullmatch(r'tokens-[0-9a-f]{64}',account):
            raise SafeError('Keychain account refused')
        if payload is not None and (not isinstance(payload,bytes) or len(payload)>50000):
            raise SafeError('Keychain record refused')
        allocated=[]
        cf=None
        try:
            cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            security=C.CDLL('/System/Library/Frameworks/Security.framework/Security')
            for name,args,result in [('CFStringCreateWithCString',[C.c_void_p,C.c_char_p,C.c_uint32],C.c_void_p),
                     ('CFDataCreate',[C.c_void_p,C.c_void_p,C.c_long],C.c_void_p),
                     ('CFDictionaryCreate',[C.c_void_p,C.POINTER(C.c_void_p),C.POINTER(C.c_void_p),C.c_long,C.c_void_p,C.c_void_p],C.c_void_p),
                     ('CFDataGetLength',[C.c_void_p],C.c_long),('CFDataGetBytePtr',[C.c_void_p],C.c_void_p),('CFRelease',[C.c_void_p],None)]:
                function=getattr(cf,name);function.argtypes=args;function.restype=result
            for name,args in [('SecItemAdd',[C.c_void_p,C.c_void_p]),('SecItemCopyMatching',[C.c_void_p,C.POINTER(C.c_void_p)]),('SecItemUpdate',[C.c_void_p,C.c_void_p])]:
                function=getattr(security,name);function.argtypes=args;function.restype=C.c_int32
            def constant(lib,name):return C.c_void_p.in_dll(lib,name).value
            def string(value):
                pointer=cf.CFStringCreateWithCString(None,value.encode(),0x08000100)
                if not pointer:raise SafeError('Keychain preparation failed')
                allocated.append(pointer);return pointer
            def dictionary(pairs):
                keys=(C.c_void_p*len(pairs))(*(constant(security,k) for k,v in pairs))
                values=(C.c_void_p*len(pairs))(*(v for k,v in pairs))
                pointer=cf.CFDictionaryCreate(None,keys,values,len(pairs),
                     C.addressof(C.c_byte.in_dll(cf,'kCFTypeDictionaryKeyCallBacks')),
                     C.addressof(C.c_byte.in_dll(cf,'kCFTypeDictionaryValueCallBacks')))
                if not pointer:raise SafeError('Keychain preparation failed')
                allocated.append(pointer);return pointer
            base=[('kSecClass',constant(security,'kSecClassGenericPassword')),
                  ('kSecAttrService',string('tesla-connector-fleet')),('kSecAttrAccount',string(account)),
                  ('kSecAttrSynchronizable',constant(cf,'kCFBooleanFalse'))]
            if payload is None:
                query=dictionary(base+[('kSecReturnData',constant(cf,'kCFBooleanTrue')),
                        ('kSecMatchLimit',constant(security,'kSecMatchLimitOne')),
                        ('kSecUseAuthenticationUI',constant(security,'kSecUseAuthenticationUIFail'))])
                result=C.c_void_p()
                status=security.SecItemCopyMatching(query,C.byref(result))
                if result.value:allocated.append(result.value)
                if status!=0 or not result.value:raise SafeError('Protected credentials unavailable or Keychain locked')
                size=cf.CFDataGetLength(result)
                if not 0<size<=50000:raise SafeError('Keychain record refused')
                return C.string_at(cf.CFDataGetBytePtr(result),size)
            buffer=C.create_string_buffer(payload)
            data=cf.CFDataCreate(None,buffer,len(payload))
            if not data:raise SafeError('Keychain preparation failed')
            allocated.append(data)
            attributes=[('kSecValueData',data),('kSecAttrAccessible',constant(security,'kSecAttrAccessibleWhenUnlockedThisDeviceOnly'))]
            status=security.SecItemAdd(dictionary(base+attributes),None)
            if status==-25299 and not add_only: # Existing token record: atomic protected replacement.
                query=dictionary(base+[('kSecUseAuthenticationUI',constant(security,'kSecUseAuthenticationUIFail'))])
                status=security.SecItemUpdate(query,dictionary(attributes))
            if status!=0:raise SafeError('Keychain refused persistence; entry not confirmed')
        except SafeError:raise
        except Exception:raise SafeError('Protected Keychain unavailable') from None
        finally:
            if cf is not None:
                for pointer in reversed(allocated):cf.CFRelease(pointer)

    def get(self,account):
        try:return json.loads(self.operation(account))
        except SafeError:raise
        except Exception:raise SafeError('Protected credential record invalid') from None

    def put(self,account,value,add_only=False):
        try:payload=json.dumps(value,allow_nan=False).encode()
        except Exception:raise SafeError('Protected credential record invalid') from None
        self.operation(account,payload,add_only)


def add_tesla_credentials(client_id,client_secret,backend=None):
    value=credentials({'client_id':client_id,'client_secret':client_secret})
    (backend or MacKeychain()).put('tesla-client',value,add_only=True)


class KeychainTokenVault:
    def __init__(self,backend,owner):
        from .storage import digest
        self.backend,self.owner=backend,digest(owner)
        self.account='tokens-'+self.owner

    def save(self,tokens):
        try:self.backend.put(self.account,{'access_token':tokens.access_token,'refresh_token':tokens.refresh_token,
                          'expires_at':tokens.expires_at,'scopes':sorted(tokens.scopes)})
        except Exception:raise SafeError('Protected token persistence failed') from None

    def load(self):
        from .oauth import token_response, ALLOWED_SCOPES
        try:return token_response(self.backend.get(self.account),ALLOWED_SCOPES,0,stored=True)
        except Exception:raise SafeError('Protected tokens unavailable or invalid') from None
