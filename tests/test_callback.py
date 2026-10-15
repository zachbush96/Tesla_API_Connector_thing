import unittest
from unittest.mock import Mock
from tesla_connector.callback import CallbackBoundary, BrowserIdentity
from tesla_connector.oauth import REDIRECT


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.oauth = Mock()
        self.boundary = CallbackBoundary(self.oauth, 'synthetic-owner')
        self.identity = BrowserIdentity('synthetic-owner', 'synthetic-session')

    def test_authenticated_callback_clean_redirect(self):
        status, headers, body = self.boundary.handle('GET', REDIRECT+'?state=synthetic&code=synthetic', self.identity)
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/setup/complete')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(body, {})
        self.oauth.callback.assert_called_once()

    def test_forged_missing_or_wrong_owner(self):
        for identity in (None, {'owner':'synthetic-owner'}, BrowserIdentity('other', 'session'), BrowserIdentity('synthetic-owner', '')):
            self.assertEqual(self.boundary.handle('GET', REDIRECT, identity)[0], 401)
        self.oauth.callback.assert_not_called()

    def test_target_fragment_size_rejected(self):
        for url in ('https://evil.invalid/oauth/callback', REDIRECT+'#fragment', REDIRECT+'?'+'x'*8192, REDIRECT.replace('https:', 'http:')):
            self.assertEqual(self.boundary.handle('GET', url, self.identity)[0], 400)
        self.oauth.callback.assert_not_called()

    def test_method_refused(self):
        self.assertEqual(self.boundary.handle('POST', REDIRECT, self.identity)[0], 405)
        self.oauth.callback.assert_not_called()

    def test_errors_redacted(self):
        self.oauth.callback.side_effect = RuntimeError('synthetic-private-code-token-location')
        response = self.boundary.handle('GET', REDIRECT, self.identity)
        self.assertEqual(response[0], 400)
        self.assertNotIn('synthetic-private', repr(response))
