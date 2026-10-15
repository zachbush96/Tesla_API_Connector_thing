import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock
from tesla_connector.storage import PrivateStore
from tesla_connector.oauth import OAuthClient, MemoryVault, Tokens
from tesla_connector.renewal import Renewal
from tesla_connector.service import SafeError

class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name).chmod(0o700)
        self.store = PrivateStore(self.tmp.name, clock=lambda: 1000)
        self.transport = Mock()
        self.oauth = OAuthClient(self.store, 'owner', 'client', 'secret', MemoryVault('owner'), self.transport)
        self.scopes = frozenset(('openid', 'vehicle_device_data', 'offline_access'))
        with self.store.transaction() as db:
            db.execute('INSERT INTO refresh_state VALUES (?, ?, 1)', (self.oauth.owner, 'ready'))
    def tearDown(self):
        self.tmp.cleanup()
    def test_near_expiry_refreshes_once_then_waits(self):
        self.oauth.vault.save(Tokens('access', 'refresh-one', 1200, self.scopes))
        self.transport.exchange.return_value = {'access_token': 'new', 'refresh_token': 'refresh-two', 'expires_in': 3600}
        renewal = Renewal(self.oauth)
        self.assertEqual(renewal.tick(), 'refreshed')
        self.assertEqual(renewal.tick(), 'valid')
        self.assertEqual(self.transport.exchange.call_count, 1)
    def test_no_offline_grant_does_not_exchange(self):
        self.oauth.vault.save(Tokens('access', None, 900, self.scopes - {'offline_access'}))
        self.assertEqual(Renewal(self.oauth).tick(), 'reauthorization-required')
        self.transport.exchange.assert_not_called()
    def test_uncertain_refresh_is_not_retried(self):
        self.oauth.vault.save(Tokens('access', 'refresh-one', 900, self.scopes))
        self.transport.exchange.side_effect = OSError('synthetic network failure')
        renewal = Renewal(self.oauth)
        with self.assertRaises(SafeError): renewal.tick()
        self.assertEqual(renewal.tick(), 'reauthorization-required')
        self.assertEqual(self.transport.exchange.call_count, 1)
