"""Tesla RS256 ID-token verification using PyJWT and the fixed public JWKS."""
import json
import hashlib
import urllib.request
from .service import SafeError, NoRedirect
from .audit import strict_object

DISCOVERY = 'https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/thirdparty/.well-known/openid-configuration'
ISSUER = 'https://auth.tesla.com/oauth2/v3/nts'
# Pinned to the exact jwks_uri advertised by the documented third-party discovery.
JWKS = 'https://auth.tesla.com/oauth2/v3/discovery/thirdparty/keys'

class IdentityValidationError(SafeError):
    CODES = frozenset({'dependency','token-format','algorithm','key-fetch','key-document','key-selection','key-not-published','key-ambiguous','key-unusable','signature','issuer','audience','expiry','issued-time','required-claim','claims','nonce','unexpected'})
    def __init__(self, code):
        self.code = code if code in self.CODES else 'unexpected'
        super().__init__('OIDC validation category: ' + self.code)

class TeslaOIDCVerifier:
    def __init__(self, opener=None, audit=None):
        self.audit = audit or (lambda *_:None)
        self.key_diagnostic = None
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, token, *, audience):
        stage = 'dependency'
        try:
            import jwt
            stage = 'token-format'
            if not isinstance(token, str) or len(token) > 32000:
                raise ValueError()
            if not token.isascii() or len(token.split('.')) != 3:
                raise ValueError()
            raw_header = jwt.utils.base64url_decode(token.split('.')[0].encode())
            if len(raw_header) > 8192:
                raise ValueError()
            header = json.loads(raw_header, object_pairs_hook=strict_object)
            if not isinstance(header, dict) or jwt.get_unverified_header(token) != header:
                raise ValueError()
            # Only the header is decoded before signature validation.  # Key selection only; never trust claims.
            stage = 'algorithm'
            if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
                raise ValueError()
            self.audit('identity-header',{'token_field':'id_token','algorithm':'RS256','kid_length':len(header['kid']),'kid_ascii':header['kid'].isascii(),'kid_has_outer_whitespace':header['kid']!=header['kid'].strip(),'token_key_sha256':hashlib.sha256(header['kid'].encode()).hexdigest(),'trimmed_key_sha256':hashlib.sha256(header['kid'].strip().encode()).hexdigest()})
            self.key_diagnostic = {'token_key_sha256': hashlib.sha256(header['kid'].encode()).hexdigest(), 'published_key_sha256': [], 'matching_key_count': 0}
            matching = []
            for attempt in range(2):
                stage = 'key-fetch'
                request = urllib.request.Request(JWKS, headers={
                    'Accept': 'application/json', 'Cache-Control': 'no-cache'})
                with self.opener.open(request, timeout=10) as response:
                    raw = response.read(65537)
                stage = 'key-document'
                if len(raw) > 65536:
                    raise ValueError()
                document = json.loads(raw, object_pairs_hook=strict_object)
                if not isinstance(document, dict) or not isinstance(document.get('keys'), list):
                    raise ValueError()
                stage = 'key-selection'
                # Match raw IDs first so malformed/unsupported keys cannot disappear silently.
                candidates = [key for key in document['keys'] if isinstance(key, dict) and key.get('kid') == header['kid']]
                self.key_diagnostic = {'token_key_sha256': hashlib.sha256(header['kid'].encode()).hexdigest(),
                    'published_key_sha256': [hashlib.sha256(key['kid'].encode()).hexdigest() for key in document['keys'] if isinstance(key, dict) and isinstance(key.get('kid'), str)],
                    'matching_key_count': len(candidates)}
                self.audit('identity-keys',{**self.key_diagnostic,'key_count':len(document['keys'])})
                if len(candidates) > 1:
                    raise IdentityValidationError('key-ambiguous')
                if not candidates:
                    if attempt == 0:
                        continue  # One bounded refresh for publication/rotation; no token exchange retry.
                    raise IdentityValidationError('key-not-published')
                candidate = candidates[0]
                if candidate.get('kty') != 'RSA' or candidate.get('alg', 'RS256') != 'RS256' or candidate.get('use', 'sig') != 'sig' or ('key_ops' in candidate and 'verify' not in candidate['key_ops']):
                    raise IdentityValidationError('key-unusable')
                key = jwt.PyJWK.from_dict(candidate, algorithm='RS256')
                matching = [key]
                break
            stage = 'claims'
            claims = jwt.decode(token, matching[0].key, algorithms=['RS256'], audience=audience,
                                issuer=ISSUER, options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce']})
            if not isinstance(claims['sub'], str) or not claims['sub'] or claims.get('azp', audience) != audience:
                raise ValueError()
            self.audit('identity-result',{'verified':True,'cause':'none'})
            return claims
        except IdentityValidationError as error:
            self.audit('identity-result',{'verified':False,'cause':error.code})
            raise
        except Exception as error:
            # Only constant categories leave this boundary, never JWT/claim/error content.
            names = {'InvalidSignatureError':'signature','InvalidIssuerError':'issuer',
                     'InvalidAudienceError':'audience','ExpiredSignatureError':'expiry',
                     'ImmatureSignatureError':'issued-time','InvalidIssuedAtError':'issued-time',
                     'MissingRequiredClaimError':'required-claim'}
            code=names.get(type(error).__name__,stage)
            detail={'verified':False,'cause':code}
            if type(error).__name__=='MissingRequiredClaimError' and getattr(error,'claim',None) in ('exp','iat','iss','aud','sub','nonce'):
                detail['missing_claim']=error.claim
            self.audit('identity-result',detail)
            raise IdentityValidationError(code) from None
