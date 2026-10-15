"""Pure callback boundary; no listener, authentication provider or network enabled."""
from dataclasses import dataclass, field
import urllib.parse
from .oauth import REDIRECT
from .service import SafeError


@dataclass(frozen=True, repr=False)
class BrowserIdentity:
    # Supplied exclusively by verified authentication/session middleware.
    owner: str
    session: str = field(repr=False)


class CallbackBoundary:
    def __init__(self, oauth, owner):
        self.oauth, self.owner = oauth, owner

    def handle(self, method, url, identity):
        headers = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                   'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
                   'X-Content-Type-Options': 'nosniff'}
        if method != 'GET':
            return 405, {**headers, 'Allow': 'GET'}, {'error': 'Method refused'}
        if (not isinstance(identity, BrowserIdentity) or identity.owner != self.owner
                or not isinstance(identity.session, str) or not identity.session):
            return 401, headers, {'error': 'Owner browser authentication required'}
        try:
            if not isinstance(url, str) or len(url) > 8192:
                raise SafeError('Invalid callback')
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme + '://' + parsed.netloc + parsed.path != REDIRECT or parsed.fragment:
                raise SafeError('Invalid callback')
            self.oauth.callback(url, identity.session)
        except Exception:
            # Never return query, code, scopes, tokens or upstream exceptions.
            return 400, headers, {'error': 'Authorization failed; restart from the owner setup page'}
        # Adapter must issue this same-origin clean redirect without rendering query content.
        return 303, {**headers, 'Location': '/setup/complete'}, {}
