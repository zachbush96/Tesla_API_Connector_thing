"""Owner-approved OAuth maintenance. No vehicle requests or interactive prompts."""
import threading
from .service import SafeError


class Renewal:
    def __init__(self, oauth):
        self.oauth = oauth
        self.stop = threading.Event()

    def tick(self):
        # Inspect and refresh only a renewable ready generation. An uncertain
        # exchange is terminal until fresh owner consent, even across restarts.
        with self.oauth.store.transaction() as db:
            now = self.oauth.store.now(db)
            row = db.execute('SELECT status FROM refresh_state WHERE owner_hash=?',
                             (self.oauth.owner,)).fetchone()
            if not row or row[0] != 'ready':
                return 'reauthorization-required'
            tokens = self.oauth.vault.load()
            if tokens.expires_at > now + 300:
                return 'valid'
            if not tokens.refresh_token or 'offline_access' not in tokens.scopes:
                return 'reauthorization-required'
        self.oauth.refresh()
        return 'refreshed'

    def run(self):
        while not self.stop.is_set():
            try:
                self.tick()
            except Exception:
                # Keychain can be locked; no UI prompts, token logging or car calls.
                # A claimed exchange already marks itself reauthorize on failure.
                pass
            self.stop.wait(60)

    def start(self):
        thread = threading.Thread(target=self.run, name='tesla-oauth-maintenance', daemon=True)
        thread.start()
        return thread
