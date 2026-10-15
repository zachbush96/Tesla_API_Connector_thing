"""Owner-controlled in-memory identity retry; never repeats code exchange or car reads."""
import json
import re
import os
import tempfile
import time
from pathlib import Path
from .oidc import IdentityValidationError
from .service import private_file

class WaitingIdentityVerifier:
    def __init__(self, verifier, *, timeout=600, interval=30, clock=time.monotonic,
                 sleep=time.sleep, event=None):
        if not 0 < timeout <= 600 or not 1 <= interval <= 60:
            raise ValueError('Invalid setup retry bounds')
        self.verifier, self.timeout, self.interval = verifier, timeout, interval
        self.clock, self.sleep, self.event = clock, sleep, event or (lambda *_: None)

    def __call__(self, token, *, audience):
        # Token remains only on this process's stack. Never log/persist it while waiting.
        deadline = self.clock() + self.timeout
        attempt = 0
        while True:
            attempt += 1
            try:
                claims = self.verifier(token, audience=audience)
                self.event('identity-verified', attempt)
                return claims
            except IdentityValidationError as error:
                self.event(error.code, attempt)
                if error.code not in ('key-not-published', 'key-fetch'):
                    raise
                remaining = deadline - self.clock()
                if remaining <= 0 or attempt >= 21:
                    raise
                self.sleep(min(self.interval, remaining))

class SetupReporter:
    """Overwrite a protected, credential-free receipt; messages are whitelist-only."""
    CODES = IdentityValidationError.CODES | frozenset({'identity-verified', 'keychain-saved'})
    def __init__(self, path, *, output=print, verifier=None):
        self.path, self.output, self.verifier = Path(path), output, verifier

    def __call__(self, code, attempt):
        code = code if code in self.CODES else 'unexpected'
        attempt = attempt if type(attempt) is int and 0 <= attempt <= 21 else 0
        report = {'category': code, 'attempt': attempt, 'checked_at_unix': int(time.time()),
                  'token_stored': code == 'keychain-saved', 'vehicle_read_performed': False}
        detail = getattr(self.verifier, 'key_diagnostic', None)
        if isinstance(detail, dict):
            token_key = detail.get('token_key_sha256')
            keys = detail.get('published_key_sha256')
            count = detail.get('matching_key_count')
            if isinstance(token_key, str) and re.fullmatch('[a-f0-9]{64}', token_key) and isinstance(keys, list) and len(keys) <= 64 and all(isinstance(key, str) and re.fullmatch('[a-f0-9]{64}', key) for key in keys) and type(count) is int and 0 <= count <= 64:
                report['signing_key_comparison'] = {'token_key_sha256': token_key, 'published_key_sha256': keys, 'matching_key_count': count}
        if self.path.exists():
            private_file(self.path)  # Refuse unsafe existing file/symlink.
        fd, temporary = tempfile.mkstemp(prefix='.setup-report-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w') as output:
                json.dump(report, output); output.flush(); os.fsync(output.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        if code in ('key-not-published', 'key-fetch'):
            self.output(f'Identity attempt {attempt}: {code}; keeping token in memory and waiting for fresh keys. Ctrl-C stops.')
        else:
            self.output(f'Setup status: {code}.')
