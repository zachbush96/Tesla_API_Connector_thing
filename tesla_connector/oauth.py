"""Tesla OAuth lifecycle; no network transport is enabled in this prototype."""
import json
import os
import re
import secrets
import stat
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from .service import SafeError, private_file
from .storage import digest

AUTH_URL = 'https://auth.tesla.com/oauth2/v3/authorize'
TOKEN_URL = 'https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token'
from .settings import PUBLIC_ORIGIN
REDIRECT = PUBLIC_ORIGIN + '/oauth/callback'
ALLOWED_SCOPES = {'openid', 'vehicle_device_data', 'vehicle_location', 'vehicle_cmds', 'vehicle_charging_cmds', 'offline_access'}


@dataclass(frozen=True, repr=False)
class Tokens:
    access_token: str
    refresh_token: str | None
    expires_at: float
    scopes: frozenset


class MemoryVault:
    """Default ephemeral vault; used in synthetic tests and local mock integration."""
    def __init__(self, owner=None):
        self.owner = digest(owner) if owner else None
        self._tokens = None

    def load(self):
        if self._tokens is None:
            raise SafeError('No authorized token available')
        return self._tokens

    def save(self, tokens):
        self._tokens = tokens


class PrivateFileVault:
    """Optional atomic owner-only storage. No encryption; use approved Keychain broker for production."""
    def __init__(self, store, owner):
        self.store = store
        self.owner = digest(owner)
        self.path = store.root / ('oauth-tokens-' + self.owner + '.json')

    def save(self, tokens):
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix='.token-', dir=self.store.root)
            with os.fdopen(fd, 'w') as out:
                json.dump({'access_token': tokens.access_token, 'refresh_token': tokens.refresh_token,
                           'expires_at': tokens.expires_at, 'scopes': sorted(tokens.scopes)}, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
            temporary = None
            directory = os.open(self.store.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, ValueError):
            raise SafeError('Protected token persistence failed') from None
        finally:
            if temporary:
                os.unlink(temporary)

    def load(self):
        try:
            data = json.loads(private_file(self.path))
            return token_response(data, set(data['scopes']), now=0, stored=True)
        except (ValueError, KeyError, TypeError):
            raise SafeError('Protected token state invalid') from None


class DisabledOAuthTransport:
    def exchange(self, url, form):
        raise SafeError('Live OAuth exchange disabled')


class OAuthClient:
    def __init__(self, store, owner, client_id, client_secret, vault=None, transport=None, region='na', verifier=None, audit=None):
        if not owner or not client_id or not client_secret or region not in ('na', 'eu', 'cn'):
            raise SafeError('OAuth configuration incomplete')
        self.audit = audit or (lambda *_:None)
        self.store, self.owner = store, digest(owner)
        self.client_id, self.client_secret = client_id, client_secret
        self.vault = vault if vault is not None else MemoryVault(owner)
        if getattr(self.vault, 'owner', None) is None:
            self.vault.owner = self.owner
        if self.vault.owner != self.owner:
            raise SafeError('Token vault belongs to another owner')
        self.transport = transport if transport is not None else DisabledOAuthTransport()
        self.verifier = verifier
        suffix = 'cn' if region == 'cn' else 'com'
        self.audience = f'https://fleet-api.prd.{region}.vn.cloud.tesla.{suffix}'

    def begin(self, browser_session, scopes=('openid', 'vehicle_device_data')):
        scopes = set(scopes)
        if not isinstance(browser_session, str) or not browser_session or 'openid' not in scopes or not scopes <= ALLOWED_SCOPES:
            raise SafeError('Invalid OAuth request')
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.transaction() as db:
            now = self.store.now(db)
            db.execute('DELETE FROM oauth_states WHERE expires<=?', (now,))
            if db.execute('SELECT count(*) FROM oauth_states').fetchone()[0] >= 128:
                raise SafeError('OAuth request capacity reached')
            db.execute('INSERT INTO oauth_states VALUES (?,?,?,?,?,?)',
                       (digest(state), self.owner, digest(browser_session), digest(nonce), ' '.join(sorted(scopes)), now + 300))
        self.audit('authorize',{'nonce_requested':True,'region':self.audience.split('.')[2], 'client_id_sha256':__import__('hashlib').sha256(self.client_id.encode()).hexdigest(),'audience_sha256':__import__('hashlib').sha256(self.audience.encode()).hexdigest()})
        # Sensitive authorization URL belongs only in a private owner browser, never logs/reports.
        return AUTH_URL + '?' + urllib.parse.urlencode({'response_type': 'code', 'client_id': self.client_id,
                     'redirect_uri': REDIRECT, 'scope': ' '.join(sorted(scopes)), 'state': state, 'nonce': nonce,
                     'require_requested_scopes': 'true', 'prompt_missing_scopes': 'true'})

    def callback(self, callback_url, browser_session):
        try:
            parsed = urllib.parse.urlsplit(callback_url)
            if parsed.scheme + '://' + parsed.netloc + parsed.path != REDIRECT or parsed.fragment:
                raise SafeError('Invalid OAuth callback target')
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True, max_num_fields=8)
            if any(len(v) != 1 for v in query.values()) or set(query) - {'state', 'code', 'error', 'error_description', 'iss', 'issuer'}:
                raise SafeError('Invalid OAuth callback parameters')
            if any(query[key][0] != 'https://auth.tesla.com/oauth2/v3' for key in ('iss', 'issuer') if key in query):
                raise SafeError('OAuth issuer mismatch')
            state = query.get('state', [''])[0]
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', state) or not isinstance(browser_session, str) or not browser_session:
                raise SafeError('Invalid OAuth state')
        except ValueError:
            raise SafeError('Invalid OAuth callback') from None
        valid = False
        with self.store.transaction() as db:
            now = self.store.now(db)
            row = db.execute('SELECT owner_hash,session_hash,nonce_hash,scopes,expires FROM oauth_states WHERE state_hash=?', (digest(state),)).fetchone()
            db.execute('DELETE FROM oauth_states WHERE state_hash=?', (digest(state),))
            valid = row is not None and row[0] == self.owner and row[1] == digest(browser_session) and now < row[4]
        if not valid:
            raise SafeError('OAuth state expired, consumed or mismatched')
        if 'error' in query or set(query) - {'iss', 'issuer'} != {'state', 'code'}:
            raise SafeError('Owner denied authorization or callback incomplete')
        code = query['code'][0]
        if not code or len(code) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in code):
            raise SafeError('Invalid authorization code')
        self.audit('callback',{'callback_issuer_matches':True})
        scopes = set(row[3].split())
        exchanged_at = self.store.clock()
        response = self._exchange({'grant_type': 'authorization_code', 'client_id': self.client_id,
                       'client_secret': self.client_secret, 'code': code, 'audience': self.audience, 'redirect_uri': REDIRECT, 'scope': ' '.join(sorted(scopes))})
        self.audit('token-fields',{'id_token_present':isinstance(response.get('id_token'),str) and bool(response['id_token']),'access_token_present':isinstance(response.get('access_token'),str) and bool(response['access_token']),'refresh_token_present':bool(response.get('refresh_token')),'id_access_identical':bool(response.get('id_token')) and response.get('id_token')==response.get('access_token'),'scope_present':'scope' in response,'bearer_type':'missing' if 'token_type' not in response else 'bearer' if isinstance(response['token_type'],str) and response['token_type'].lower()=='bearer' else 'other'})
        if response.get('id_token'):
            # Do not decode unverified JWTs. Production must provide a vetted OIDC/JWKS verifier.
            if self.verifier is None:
                raise SafeError('Verified OIDC token validation required')
            try:
                claims = self.verifier(response['id_token'], audience=self.client_id)
            except Exception as error:
                from .oidc import IdentityValidationError
                if isinstance(error, IdentityValidationError):
                    raise
                raise IdentityValidationError('unexpected') from None
            if not isinstance(claims, dict) or not isinstance(claims.get('nonce'), str) or digest(claims['nonce']) != row[2]:
                from .oidc import IdentityValidationError
                self.audit('identity-result',{'verified':False,'cause':'nonce'})
                raise IdentityValidationError('nonce')
        tokens = token_response(response, scopes, now=exchanged_at)
        if tokens.expires_at <= self.store.clock() + 60:
            from .oidc import IdentityValidationError
            self.audit('identity-result',{'verified':False,'cause':'expiry'})
            raise IdentityValidationError('expiry')
        with self.store.transaction() as db:
            status = db.execute('SELECT status FROM refresh_state WHERE owner_hash=?', (self.owner,)).fetchone()
            if status and status[0] == 'refreshing':
                raise SafeError('Token lifecycle busy; retry owner authorization later')
            self.vault.save(tokens)
            self.audit('vault',{'stored':True})
            db.execute('INSERT INTO refresh_state VALUES (?, ?, 1) ON CONFLICT(owner_hash) DO UPDATE SET status=excluded.status,generation=generation+1', (self.owner, 'ready'))
        return {'authorized': True, 'persistent': tokens.refresh_token is not None, 'scopes': sorted(tokens.scopes)}

    def _exchange(self, form):
        try:
            response = self.transport.exchange(TOKEN_URL, form)
            if not isinstance(response, dict):
                raise SafeError('Invalid token response')
            return response
        except Exception:
            raise SafeError('OAuth exchange failed or disabled; details withheld') from None

    def access_token(self):
        return self.authorization()['bearer']

    def authorization(self, required_scopes=()):
        """Internal atomic current-generation snapshot; never refresh or expose via MCP."""
        required = frozenset(required_scopes)
        if any(not isinstance(scope, str) for scope in required) or not required <= ALLOWED_SCOPES:
            raise SafeError('Required authorization scope invalid')
        with self.store.transaction() as db:
            now = self.store.now(db)
            row = db.execute('SELECT status,generation FROM refresh_state WHERE owner_hash=?', (self.owner,)).fetchone()
            if not row or row[0] != 'ready':
                raise SafeError('Authorization unavailable; owner reauthorization required')
            tokens = self.vault.load()
            if tokens.expires_at <= now + 60:
                raise SafeError('Token expired or near expiry; explicit refresh required')
            if not required <= tokens.scopes:
                raise SafeError('Required authorization permission unavailable')
            return {'bearer':tokens.access_token, 'scopes':tokens.scopes, 'generation':row[1],
                    'expires_at':tokens.expires_at}  # Protected local integration only.

    def refresh(self):
        # Claim durably BEFORE exchange. Crash/uncertainty fails closed, never retries old token.
        with self.store.transaction() as db:
            self.store.now(db)
            row = db.execute('SELECT status,generation FROM refresh_state WHERE owner_hash=?', (self.owner,)).fetchone()
            if not row or row[0] != 'ready':
                raise SafeError('Refresh unavailable; owner reauthorization required')
            old = self.vault.load()
            if old.refresh_token is None or 'offline_access' not in old.scopes:
                raise SafeError('Persistent refresh permission not granted')
            generation = row[1]
            db.execute('UPDATE refresh_state SET status=? WHERE owner_hash=?', ('refreshing', self.owner))
        try:
            exchanged_at = self.store.clock()
            response = self._exchange({'grant_type': 'refresh_token', 'client_id': self.client_id, 'refresh_token': old.refresh_token})
            new = token_response(response, set(old.scopes), now=exchanged_at)
            if new.expires_at <= self.store.clock() + 60:
                raise SafeError('Refreshed token already expired')
            if new.refresh_token == old.refresh_token:
                raise SafeError('Refresh token rotation missing')
            with self.store.transaction() as db:
                current = db.execute('SELECT status,generation FROM refresh_state WHERE owner_hash=?', (self.owner,)).fetchone()
                if current != ('refreshing', generation):
                    raise SafeError('Refresh generation mismatch')
                self.vault.save(new)
                changed = db.execute('UPDATE refresh_state SET status=?,generation=? WHERE owner_hash=? AND status=? AND generation=?',
                                     ('ready', generation + 1, self.owner, 'refreshing', generation)).rowcount
                if changed != 1:
                    raise SafeError('Refresh generation mismatch')
            return {'refreshed': True, 'scopes': sorted(new.scopes)}
        except Exception:
            with self.store.transaction() as db:
                db.execute('UPDATE refresh_state SET status=? WHERE owner_hash=? AND generation=?', ('reauthorize', self.owner, generation))
            raise SafeError('Refresh outcome uncertain or rejected; owner reauthorization required') from None


def token_response(response, requested, now, stored=False):
    if not isinstance(response, dict):
        raise SafeError('Invalid token response')
    if not stored and 'token_type' in response and (not isinstance(response['token_type'], str) or response['token_type'].lower() != 'bearer'):
        raise SafeError('Unsupported token type')
    access = response.get('access_token')
    refresh = response.get('refresh_token')
    if not isinstance(access, str) or not re.fullmatch(r'[!-~]{1,16000}', access):
        raise SafeError('Invalid access token response')
    if refresh is not None and (not isinstance(refresh, str) or not re.fullmatch(r'[!-~]{1,16000}', refresh)):
        raise SafeError('Invalid refresh token response')
    scopes_raw = response.get('scopes') if stored else response.get('scope', ' '.join(sorted(requested)))
    if not isinstance(scopes_raw, list if stored else str):
        raise SafeError('Granted scopes must be explicit')
    if stored and any(not isinstance(value, str) for value in scopes_raw):
        raise SafeError('Invalid stored scopes')
    scopes = set(scopes_raw) if stored else set(scopes_raw.split())
    if 'openid' not in scopes or not scopes <= requested or not scopes <= ALLOWED_SCOPES:
        raise SafeError('Unexpected granted scopes')
    if ('offline_access' in scopes) != (refresh is not None):
        raise SafeError('Refresh token and permission mismatch')
    if stored:
        expires = response.get('expires_at')
        if type(expires) not in (int, float) or not 0 < expires < 1e12:
            raise SafeError('Invalid token expiry')
    else:
        duration = response.get('expires_in')
        if type(duration) is not int or not 1 <= duration <= 86400:
            raise SafeError('Invalid token lifetime')
        expires = now + duration
    return Tokens(access, refresh, expires, frozenset(scopes))
