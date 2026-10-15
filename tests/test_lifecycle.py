import concurrent.futures
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import Mock, patch
from tesla_connector.commands import CommandAdapter, Intent, MockProxy
from tesla_connector.oauth import OAuthClient, PrivateFileVault, MemoryVault, Tokens, REDIRECT, TOKEN_URL
from tesla_connector.operator import OperatorConsole
from tesla_connector.service import SafeError
from tesla_connector.storage import PrivateStore, DurableApprovalLedger, DurableBudget, digest


class DurableTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.now = 1700000000.0
        self.store = PrivateStore(self.root.name, clock=lambda: self.now)
        self.intent = Intent.build('synthetic-owner', 'AAAAAAAAAAAAAAAAA', 'preview_temperature', {'celsius': 22})

    def tearDown(self):
        self.root.cleanup()

    def test_durable_approval_survives_restart_but_not_replay(self):
        ticket = DurableApprovalLedger(self.store).approve(self.intent)
        restarted = DurableApprovalLedger(PrivateStore(self.root.name, clock=lambda: self.now))
        restarted.consume(ticket, self.intent)
        with self.assertRaises(SafeError):
            DurableApprovalLedger(self.store).consume(ticket, self.intent)

    def test_concurrent_independent_connections_consume_once(self):
        ticket = DurableApprovalLedger(self.store).approve(self.intent)
        def consume(_):
            ledger = DurableApprovalLedger(PrivateStore(self.root.name, clock=lambda: self.now))
            try:
                ledger.consume(ticket, self.intent)
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(consume, range(8))), 1)

    def test_mismatch_burns_durably_and_expiry_clock_fail_closed(self):
        ledger = DurableApprovalLedger(self.store)
        ticket = ledger.approve(self.intent)
        changed = Intent.build('synthetic-owner', 'BBBBBBBBBBBBBBBBB', 'preview_temperature', {'celsius': 22})
        with self.assertRaises(SafeError):
            ledger.consume(ticket, changed)
        with self.assertRaises(SafeError):
            ledger.consume(ticket, self.intent)
        ticket = ledger.approve(self.intent)
        self.now += 60
        with self.assertRaises(SafeError):
            ledger.consume(ticket, self.intent)
        self.now -= 100
        with self.assertRaises(SafeError) as caught:
            ledger.approve(self.intent)
        self.assertIn('rollback', str(caught.exception))

    def test_budget_default_zero_atomic_restart_and_month(self):
        budget = DurableBudget(self.store, 'synthetic-owner')
        with self.assertRaises(SafeError):
            budget.reserve('data')
        budget.configure(4000)
        def reserve(_):
            try:
                DurableBudget(PrivateStore(self.root.name, clock=lambda: self.now), 'synthetic-owner').reserve('data')
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(reserve, range(8))), 2)
        self.assertEqual(DurableBudget(self.store, 'synthetic-owner').spent(), 4000)
        with self.assertRaises(SafeError):
            budget.reserve('commands')
        self.now += 40 * 86400
        self.assertEqual(budget.spent(), 0)
        budget.reserve('commands')
        self.assertEqual(budget.spent(), 1000)
        with self.assertRaises(SafeError):
            budget.reserve('wake')

    def test_budget_reserves_before_mock_command_and_failure_never_refunds(self):
        ledger = DurableApprovalLedger(self.store)
        budget = DurableBudget(self.store, 'synthetic-owner')
        budget.configure(1000)
        proxy = MockProxy()
        adapter = CommandAdapter(ledger, proxy, budget)
        ticket = ledger.approve(self.intent)
        self.assertTrue(adapter.submit(self.intent, ticket, 'synthetic-token')['simulated'])
        self.assertEqual(budget.spent(), 1000)
        ticket = ledger.approve(self.intent)
        with self.assertRaises(SafeError):
            adapter.submit(self.intent, ticket, 'synthetic-token')
        with self.assertRaises(SafeError):
            ledger.consume(ticket, self.intent)
        self.assertEqual(proxy.calls, 1)

    def test_private_permissions_and_no_raw_approval_data_in_db(self):
        ledger = DurableApprovalLedger(self.store)
        ticket = ledger.approve(self.intent)
        raw = self.store.path.read_bytes()
        for secret in (ticket, self.intent.target, self.intent.principal):
            self.assertNotIn(secret.encode(), raw)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.store.path.chmod(0o644)
        with self.assertRaises(SafeError):
            PrivateStore(self.root.name)
        self.store.path.chmod(0o600)
        Path(self.root.name).chmod(0o755)
        with self.assertRaises(SafeError):
            PrivateStore(self.root.name)
        Path(self.root.name).chmod(0o700)

    def test_operator_exact_binding_denial_and_no_identifier_ticket_output(self):
        ledger = DurableApprovalLedger(self.store)
        console = OperatorConsole(ledger, 'synthetic-owner', self.intent.target)
        class Fixture:
            text = ''
            def write(self, text):
                self.text += text
            def flush(self):
                pass
            def readline(self, limit):
                return 'APPROVE ' + self_intent.binding().hex()[:12] + '\n'
        self_intent = self.intent
        ui = Fixture()
        ticket = console.approve(self.intent, ui=ui)
        self.assertNotIn(ticket, ui.text)
        self.assertNotIn(self.intent.target, ui.text)
        self.assertIn('22 degrees Celsius', ui.text)
        ledger.consume(ticket, self.intent)
        with self.assertRaises(SafeError):
            console.approve(self.intent, ui=io.StringIO('yes\n'))
        wrong = Intent.build('other-owner', self.intent.target, 'preview_temperature', {'celsius': 22})
        with self.assertRaises(SafeError):
            console.approve(wrong, ui=Fixture())
        with patch('builtins.open', side_effect=OSError()):
            with self.assertRaises(SafeError):
                console.approve(self.intent)


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.now = 1700000000.0
        self.store = PrivateStore(self.root.name, clock=lambda: self.now)
        self.transport = Mock()
        self.transport.exchange.return_value = {'access_token': 'synthetic-access', 'expires_in': 3600,
                                                'scope': 'openid vehicle_device_data'}
        self.vault = PrivateFileVault(self.store, 'synthetic-owner')
        self.client = OAuthClient(self.store, 'synthetic-owner', 'synthetic-client', 'synthetic-secret',
                                  self.vault, self.transport)

    def tearDown(self):
        self.root.cleanup()

    def request(self, scopes=('openid', 'vehicle_device_data')):
        url = self.client.begin('synthetic-browser', scopes)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        callback = REDIRECT + '?' + urllib.parse.urlencode({'state': query['state'][0], 'code': 'synthetic-code'})
        return query, callback

    def authorize(self, persistent=False):
        scopes = ('openid', 'vehicle_device_data', 'offline_access') if persistent else ('openid', 'vehicle_device_data')
        if persistent:
            self.transport.exchange.return_value = {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh-1',
                                                    'expires_in': 3600, 'scope': ' '.join(scopes)}
        _, callback = self.request(scopes)
        return self.client.callback(callback, 'synthetic-browser')

    def test_minimal_authorize_and_correct_exchange_contract(self):
        query, callback = self.request()
        self.assertNotIn('offline_access', query['scope'][0])
        self.assertEqual(query['redirect_uri'], [REDIRECT])
        self.assertTrue(self.client.callback(callback, 'synthetic-browser')['authorized'])
        url, form = self.transport.exchange.call_args.args
        self.assertEqual(url, TOKEN_URL)
        self.assertEqual(form['grant_type'], 'authorization_code')
        self.assertEqual(form['redirect_uri'], REDIRECT)
        self.assertEqual(form['audience'], 'https://fleet-api.prd.na.vn.cloud.tesla.com')
        self.assertEqual(self.client.access_token(), 'synthetic-access')
        self.assertEqual(self.vault.path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'synthetic-access', self.store.path.read_bytes())
        self.assertNotIn('synthetic-access', repr(self.vault.load()))

    def test_callback_replay_wrong_browser_owner_target_and_duplicate_params(self):
        _, callback = self.request()
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'other-browser')
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        self.transport.exchange.assert_not_called()
        _, callback = self.request()
        for altered in (callback.replace('connector.example.invalid', 'attacker.invalid'), callback + '&state=duplicate', callback + '#fragment'):
            with self.assertRaises(SafeError):
                self.client.callback(altered, 'synthetic-browser')
        self.client.callback(callback, 'synthetic-browser')
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        self.assertEqual(self.transport.exchange.call_count, 1)

    def test_expired_state_and_owner_denial_never_exchange(self):
        _, callback = self.request()
        self.now += 300
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        query, _ = self.request()
        denial = REDIRECT + '?' + urllib.parse.urlencode({'state': query['state'][0], 'error': 'access_denied', 'error_description': 'private-detail'})
        with self.assertRaises(SafeError) as caught:
            self.client.callback(denial, 'synthetic-browser')
        self.assertNotIn('private-detail', str(caught.exception))
        self.transport.exchange.assert_not_called()

    def test_default_transport_disabled_and_state_burned(self):
        client = OAuthClient(self.store, 'synthetic-owner', 'synthetic-client', 'synthetic-secret')
        url = client.begin('synthetic-browser')
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['state'][0]
        callback = REDIRECT + '?' + urllib.parse.urlencode({'state': state, 'code': 'synthetic-code'})
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')):
            with self.assertRaises(SafeError):
                client.callback(callback, 'synthetic-browser')
        with self.assertRaises(SafeError):
            client.callback(callback, 'synthetic-browser')

    def test_verified_nonce_required_when_id_token_returned(self):
        query, callback = self.request()
        self.transport.exchange.return_value['id_token'] = 'synthetic-id-token'
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        query, callback = self.request()
        self.client.verifier = Mock(return_value={'nonce': 'wrong'})
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        query, callback = self.request()
        self.client.verifier = Mock(return_value={'nonce': query['nonce'][0]})
        self.assertTrue(self.client.callback(callback, 'synthetic-browser')['authorized'])
        self.client.verifier.assert_called_with('synthetic-id-token', audience='synthetic-client')

    def test_refresh_rotates_atomically_and_survives_restart(self):
        self.authorize(True)
        self.transport.exchange.return_value = {'access_token': 'synthetic-access-2', 'refresh_token': 'synthetic-refresh-2',
                                                'expires_in': 3600, 'scope': 'openid vehicle_device_data offline_access'}
        self.assertTrue(self.client.refresh()['refreshed'])
        self.assertEqual(self.transport.exchange.call_args.args[1]['refresh_token'], 'synthetic-refresh-1')
        restarted = OAuthClient(PrivateStore(self.root.name, clock=lambda: self.now), 'synthetic-owner', 'synthetic-client',
                                'synthetic-secret', PrivateFileVault(self.store, 'synthetic-owner'))
        self.assertEqual(restarted.access_token(), 'synthetic-access-2')
        self.assertEqual(restarted.vault.load().refresh_token, 'synthetic-refresh-2')
        self.now += 3541
        with self.assertRaises(SafeError):
            restarted.access_token()

    def test_no_refresh_without_persistent_permission(self):
        self.authorize(False)
        self.transport.exchange.reset_mock()
        with self.assertRaises(SafeError):
            self.client.refresh()
        self.transport.exchange.assert_not_called()

    def test_refresh_timeout_or_persistence_failure_requires_reauth_no_retry(self):
        self.authorize(True)
        self.transport.exchange.reset_mock()
        self.transport.exchange.side_effect = TimeoutError('private-refresh-token')
        with self.assertRaises(SafeError) as caught:
            self.client.refresh()
        self.assertNotIn('private-refresh-token', str(caught.exception))
        with self.assertRaises(SafeError):
            self.client.refresh()
        with self.assertRaises(SafeError):
            self.client.access_token()
        self.assertEqual(self.transport.exchange.call_count, 1)

    def test_cross_process_refresh_claim_prevents_parallel_rotation(self):
        self.authorize(True)
        entered, release = threading.Event(), threading.Event()
        response = {'access_token': 'synthetic-access-2', 'refresh_token': 'synthetic-refresh-2', 'expires_in': 3600,
                    'scope': 'openid vehicle_device_data offline_access'}
        def exchange(url, form):
            entered.set()
            release.wait(3)
            return response
        self.transport.exchange.side_effect = exchange
        other = OAuthClient(PrivateStore(self.root.name, clock=lambda: self.now), 'synthetic-owner', 'synthetic-client',
                            'synthetic-secret', PrivateFileVault(self.store, 'synthetic-owner'), self.transport)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.client.refresh)
            self.assertTrue(entered.wait(2))
            with self.assertRaises(SafeError):
                other.refresh()
            release.set()
            self.assertTrue(first.result(3)['refreshed'])
        self.assertEqual(self.transport.exchange.call_count, 2)  # Initial authorization + one refresh.

    def test_callback_cannot_replace_tokens_during_refresh(self):
        self.authorize(True)
        _, callback = self.request()
        with self.store.transaction() as db:
            db.execute('UPDATE refresh_state SET status=? WHERE owner_hash=?', ('refreshing', self.client.owner))
        self.transport.exchange.return_value = {'access_token': 'synthetic-new-grant', 'expires_in': 3600,
                                                'scope': 'openid vehicle_device_data'}
        with self.assertRaises(SafeError):
            self.client.callback(callback, 'synthetic-browser')
        self.assertEqual(self.vault.load().access_token, 'synthetic-access')

    def test_unexpected_scopes_expiry_refresh_and_vault_owner_rejected(self):
        for response in ({'access_token': 'synthetic-access', 'expires_in': 3600, 'scope': 'openid user_data'},
                         {'access_token': 'synthetic-access', 'expires_in': True, 'scope': 'openid vehicle_device_data'},
                         {'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh', 'expires_in': 3600, 'scope': 'openid vehicle_device_data'}):
            _, callback = self.request()
            self.transport.exchange.return_value = response
            with self.assertRaises(SafeError):
                self.client.callback(callback, 'synthetic-browser')
        with self.assertRaises(SafeError):
            OAuthClient(self.store, 'other-owner', 'synthetic-client', 'synthetic-secret', self.vault)


if __name__ == '__main__':
    unittest.main()
