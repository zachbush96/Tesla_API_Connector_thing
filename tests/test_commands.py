import concurrent.futures
import json
import unittest
from unittest.mock import Mock, patch
from tesla_connector.commands import ApprovalLedger, CommandAdapter, DisabledNetwork, Intent, MockProxy
from tesla_connector.service import SafeError
from tesla_connector.http_mock import MockHTTPMCP, VerifiedIdentity
from tesla_connector.mcp import Session
from tesla_connector.service import Config, Service

TARGET_A = 'AAAAAAAAAAAAAAAAA'
TARGET_B = 'BBBBBBBBBBBBBBBBB'


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.ledger = ApprovalLedger(lambda: self.now)
        self.intent = Intent.build('synthetic-owner', TARGET_A, 'preview_temperature', {'celsius': 22})
        self.proxy = MockProxy()
        self.adapter = CommandAdapter(self.ledger, self.proxy)

    def test_mock_approved_request_contract(self):
        ticket = self.ledger.approve(self.intent)
        transport = Mock(simulated=True)
        transport.send.return_value = {'response': {'result': True, 'reason': 'private-detail'}}
        result = CommandAdapter(self.ledger, transport).submit(self.intent, ticket, 'synthetic-token')
        request = transport.send.call_args.args[0]
        self.assertEqual(request.full_url, f'https://localhost:4443/api/1/vehicles/{TARGET_A}/command/set_temps')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(json.loads(request.data), {'driver_temp': 22, 'passenger_temp': 22})
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertTrue(result['accepted'])
        self.assertTrue(result['simulated'])
        self.assertFalse(result['vehicle_execution_verified'])
        self.assertNotIn('private-detail', json.dumps(result))

    def test_navigation_request_contract(self):
        intent = Intent.build('synthetic-owner', TARGET_A, 'preview_navigation', {'destination': 'Synthetic private destination'})
        ticket = self.ledger.approve(intent)
        transport = Mock(simulated=True)
        transport.send.return_value = {'response': {'result': True}}
        result = CommandAdapter(self.ledger, transport).submit(intent, ticket, 'synthetic-token')
        request = transport.send.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload['type'], 'share_ext_content_raw')
        self.assertEqual(payload['value']['android.intent.extra.TEXT'], 'Synthetic private destination')
        self.assertTrue(request.full_url.endswith('/command/navigation_request'))
        self.assertNotIn('Synthetic private destination', json.dumps(result))

    def test_mcp_preview_to_separate_operator_approval_to_mock_proxy(self):
        session = Session(Service(Config()))
        session.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'}})
        session.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        for name, args in [('preview_temperature', {'celsius': 22}),
                           ('preview_navigation', {'destination': 'Synthetic private destination'})]:
            reply = session.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}})
            preview = json.loads(reply['result']['content'][0]['text'])
            self.assertFalse(preview['executed'])
            self.assertNotIn('Synthetic private destination', json.dumps(reply))
            # Synthetic trusted operator side, deliberately outside the MCP tool API.
            intent = Intent.build('synthetic-owner', TARGET_A, name, args)
            approval = self.ledger.approve(intent)
            result = self.adapter.submit(intent, approval, 'synthetic-token')
            self.assertTrue(result['simulated'])
            self.assertFalse(result['vehicle_execution_verified'])
            with self.assertRaises(SafeError):
                self.adapter.submit(intent, approval, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 2)
        tools = session.handle({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'})['result']['tools']
        self.assertFalse(any('approve' in tool['name'] or 'execute' in tool['name'] for tool in tools))

    def test_missing_approval_never_calls_proxy(self):
        for ticket in (None, '', 'true', True, 'f' * 64):
            with self.assertRaises(SafeError):
                self.adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 0)

    def test_replay_and_concurrent_consumption(self):
        ticket = self.ledger.approve(self.intent)
        def attempt(_):
            try:
                self.adapter.submit(self.intent, ticket, 'synthetic-token')
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.proxy.calls, 1)

    def test_stale_and_clock_rollback(self):
        for now in (70, 9):
            self.now = 10
            ticket = self.ledger.approve(self.intent, ttl=60)
            self.now = now
            with self.assertRaises(SafeError):
                self.adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 0)

    def test_target_principal_arguments_command_bound(self):
        variants = [Intent.build('synthetic-owner', TARGET_B, 'preview_temperature', {'celsius': 22}),
                    Intent.build('other-owner', TARGET_A, 'preview_temperature', {'celsius': 22}),
                    Intent.build('synthetic-owner', TARGET_A, 'preview_temperature', {'celsius': 23}),
                    Intent.build('synthetic-owner', TARGET_A, 'preview_navigation', {'destination': 'Synthetic place'})]
        for changed in variants:
            ticket = self.ledger.approve(self.intent)
            with self.assertRaises(SafeError):
                self.adapter.submit(changed, ticket, 'synthetic-token')
            with self.assertRaises(SafeError):
                self.adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 0)

    def test_restart_invalidates_approval(self):
        ticket = self.ledger.approve(self.intent)
        with self.assertRaises(SafeError):
            CommandAdapter(ApprovalLedger(), self.proxy).submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 0)

    def test_no_network_even_with_valid_operator_approval(self):
        ticket = self.ledger.approve(self.intent)
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')):
            with self.assertRaises(SafeError) as caught:
                CommandAdapter(self.ledger).submit(self.intent, ticket, 'synthetic-token')
        self.assertIn('disabled', str(caught.exception))
        with self.assertRaises(SafeError):
            self.adapter.submit(self.intent, ticket, 'synthetic-token')

    def test_errors_consume_approval_no_retry(self):
        transport = Mock(simulated=True)
        transport.send.side_effect = TimeoutError('private-token-and-target')
        ticket = self.ledger.approve(self.intent)
        adapter = CommandAdapter(self.ledger, transport)
        with self.assertRaises(SafeError) as caught:
            adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertIn('unknown', str(caught.exception))
        self.assertNotIn('private', str(caught.exception))
        with self.assertRaises(SafeError):
            adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(transport.send.call_count, 1)

    def test_transport_safe_error_is_not_trusted_for_redaction(self):
        ticket = self.ledger.approve(self.intent)
        transport = Mock(simulated=True)
        transport.send.side_effect = SafeError('synthetic-private-upstream-detail')
        with self.assertRaises(SafeError) as caught:
            CommandAdapter(self.ledger, transport).submit(self.intent, ticket, 'synthetic-token')
        self.assertNotIn('synthetic-private', str(caught.exception))
        with self.assertRaises(SafeError):
            self.adapter.submit(self.intent, ticket, 'synthetic-token')
        self.assertEqual(transport.send.call_count, 1)

    def test_mutated_intent_rejected_before_transport(self):
        ticket = self.ledger.approve(self.intent)
        corrupt = Intent(self.intent.principal, self.intent.target, 'set_temps', b'{"driver_temp":22,"passenger_temp":23}')
        with self.assertRaises(SafeError):
            self.adapter.submit(corrupt, ticket, 'synthetic-token')
        self.assertEqual(self.proxy.calls, 0)

    def test_rejected_and_malformed_response(self):
        for response in ({'response': {'result': False, 'reason': 'private-token'}}, {},
                         {'response': {'result': 'true'}}, {'response': []}):
            ticket = self.ledger.approve(self.intent)
            adapter = CommandAdapter(self.ledger, MockProxy(response))
            if isinstance(response.get('response'), dict) and response['response'].get('result') is False:
                self.assertFalse(adapter.submit(self.intent, ticket, 'synthetic-token')['accepted'])
            else:
                with self.assertRaises(SafeError):
                    adapter.submit(self.intent, ticket, 'synthetic-token')
            with self.assertRaises(SafeError):
                adapter.submit(self.intent, ticket, 'synthetic-token')

    def test_no_driving_security_unlock_arbitrary_payload(self):
        for command in ('door_unlock', 'remote_start_drive', 'set_sentry_mode', '../door_unlock', 'auto_conditioning_start'):
            with self.assertRaises(SafeError):
                Intent.build('synthetic-owner', TARGET_A, command, {})
            with self.assertRaises(SafeError):
                self.ledger.approve(Intent('synthetic-owner', TARGET_A, command, b'{}'))
        invalid = [b'{"driver_temp":22,"passenger_temp":23}',
                   b'{"driver_temp":22,"passenger_temp":22,"execute":true}',
                   b'{"driver_temp":true,"passenger_temp":true}', b'null']
        for payload in invalid:
            with self.assertRaises(SafeError):
                self.ledger.approve(Intent('synthetic-owner', TARGET_A, 'set_temps', payload))

    def test_ttl_capacity_and_repr_privacy(self):
        for ttl in (0, 121, True, float('nan'), float('inf')):
            with self.assertRaises(SafeError):
                self.ledger.approve(self.intent, ttl)
        for _ in range(128):
            self.ledger.approve(self.intent)
        with self.assertRaises(SafeError):
            self.ledger.approve(self.intent)
        self.now = 71
        self.ledger.approve(self.intent)
        self.assertNotIn(TARGET_A, repr(self.intent))
        self.assertNotIn('synthetic-owner', repr(self.intent))


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = MockHTTPMCP('synthetic-owner')
        self.owner = VerifiedIdentity('synthetic-owner')

    def call(self, method, params=None, identity=None):
        return self.server.post('/mcp', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                 'params': params or {}}).encode(), identity)

    def test_identity_enforced_before_any_tool(self):
        for identity, code in ((None, 401), ({'oai-authenticated-user-id': 'synthetic-owner'}, 401),
                               (VerifiedIdentity('other-owner'), 403)):
            status, _ = self.call('tools/call', {'name': 'read_location'}, identity)
            self.assertEqual(status, code)
        self.assertEqual(self.call('tools/list', identity=self.owner)[0], 200)

    def test_stateless_initialize_discovery_tool(self):
        self.assertEqual(self.call('initialize', {'protocolVersion': '2025-11-25'}, self.owner)[0], 200)
        self.assertEqual(len(self.call('tools/list', identity=self.owner)[1]['result']['tools']), 5)
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')):
            body = self.call('tools/call', {'name': 'read_battery_charging'}, self.owner)[1]
        output = json.loads(body['result']['content'][0]['text'])
        self.assertEqual(output['mode'], 'mock')
        self.assertEqual(output['battery_percent'], 72)

    def test_cannot_approve_execute_or_impersonate_via_tool_body(self):
        for name in ('approve_command', 'execute_navigation', 'door_unlock'):
            body = self.call('tools/call', {'name': name}, self.owner)[1]
            self.assertTrue(body['result']['isError'])
        status, _ = self.call('tools/call', {'name': 'read_location', 'user_id': 'synthetic-owner'})
        self.assertEqual(status, 401)

    def test_limits_parse_and_notifications(self):
        self.assertEqual(self.server.post('/mcp', b'x' * 65537, self.owner)[0], 413)
        self.assertEqual(self.server.post('/mcp', b'bad-json-private', self.owner)[0], 400)
        self.assertEqual(self.server.post('/wrong', b'{}', self.owner)[0], 404)
        self.assertEqual(self.server.post('/mcp', b'{"jsonrpc":"2.0","method":"notifications/initialized"}', self.owner), (202, None))


if __name__ == '__main__':
    unittest.main()
