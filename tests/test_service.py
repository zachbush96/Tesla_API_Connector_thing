import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch
from tesla_connector.service import Config, FleetReader, NoRedirect, SafeError, Service, command_plan, private_file
from tesla_connector.mcp import Session


class ServiceTests(unittest.TestCase):
    def test_default_never_networks(self):
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')):
            service = Service(Config())
            self.assertEqual(service.call('read_battery_charging', {})['battery_percent'], 72)
            self.assertTrue(service.call('read_location', {})['synthetic'])
            for name, args in [('preview_navigation', {'destination': 'Synthetic destination'}),
                               ('preview_temperature', {'celsius': 22})]:
                self.assertFalse(service.call(name, args)['executed'])

    def test_read_opt_in_required(self):
        with self.assertRaises(SafeError):
            Config(mode='live-read')

    def test_invalid_config(self):
        for kwargs in ({'mode': 'live'}, {'region': 'attacker.invalid'}):
            with self.assertRaises(SafeError):
                Config(**kwargs)

    def test_command_payload_contract(self):
        command, payload = command_plan('preview_navigation', {'destination': 'Synthetic destination'})
        self.assertEqual(command, 'navigation_request')
        self.assertEqual(payload['type'], 'share_ext_content_raw')
        self.assertEqual(payload['value']['android.intent.extra.TEXT'], 'Synthetic destination')
        self.assertRegex(payload['timestamp_ms'], r'^[0-9]{13}$')
        self.assertEqual(command_plan('preview_temperature', {'celsius': 22}),
                         ('set_temps', {'driver_temp': 22, 'passenger_temp': 22}))

    def test_invalid_values(self):
        for val in (True, None, '22', float('nan'), float('inf'), 10 ** 1000, 14, 29):
            with self.assertRaises(SafeError):
                Service(Config()).call('preview_temperature', {'celsius': val})
        for args in ({'destination': ''}, {'destination': 'x' * 301},
                     {'latitude': 0}, {'destination': 'place', 'execute': True}):
            with self.assertRaises(SafeError):
                Service(Config()).call('preview_navigation', args)

    def test_schema_rejects_extra_and_non_objects(self):
        for args in ([], None, {'vin': 'not-accepted'}, {'execute': True}):
            with self.assertRaises(SafeError):
                Service(Config()).call('read_location', args)

    def test_precise_data_never_leaves_service(self):
        reader = Mock()
        reader.data.return_value = {'drive_state': {'latitude': 12.345678, 'longitude': 23.456789},
                                   'vin': 'do-not-expose', 'token': 'secret'}
        out = json.dumps(Service(Config(), reader).call('read_location', {}))
        for sensitive in ('12.345678', '23.456789', 'do-not-expose', 'secret'):
            self.assertNotIn(sensitive, out)
        self.assertIn('12.3', out)

    def test_upstream_untrusted_charging_text_not_reflected(self):
        reader = Mock()
        reader.data.return_value = {'charge_state': {'battery_level': 72, 'charging_state': 'private-data',
                                                   'charge_limit_soc': 80, 'charger_power': 0}}
        out = Service(Config(), reader).call('read_battery_charging', {})
        self.assertEqual(out['charging_state'], 'Unknown')

    def test_preview_in_live_read_mode_never_calls_reader(self):
        reader = Mock()
        output = Service(Config(mode='live-read', allow_live_reads=True), reader).call(
            'preview_navigation', {'destination': 'Synthetic private destination'})
        reader.data.assert_not_called()
        self.assertNotIn('Synthetic private destination', json.dumps(output))
        self.assertFalse(output['executed'])

    def test_secret_permissions_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'secret'
            path.write_text('synthetic-test-secret')
            path.chmod(0o600)
            self.assertEqual(private_file(path), 'synthetic-test-secret')
            path.chmod(0o644)
            with self.assertRaises(SafeError):
                private_file(path)
            path.chmod(0o600)
            link = Path(root) / 'link'
            link.symlink_to(path)
            with self.assertRaises(SafeError):
                private_file(link)

    def test_live_read_budget_blocks_before_secrets_or_network(self):
        reader = FleetReader(Config('live-read', True))
        reader.attempts = 30
        with patch('tesla_connector.service.private_file', side_effect=AssertionError('must not read')):
            with self.assertRaises(SafeError) as caught:
                reader.data('charge_state')
        self.assertIn('budget', str(caught.exception))

    def test_navigation_destination_length_boundaries(self):
        for destination in ('x', 'x' * 300):
            result = Service(Config()).call('preview_navigation', {'destination': destination})
            self.assertFalse(result['executed'])

    def test_malformed_location_fails_closed(self):
        reader = Mock()
        for data in ({}, {'location_data': None}, {'location_data': {'latitude': float('inf'), 'longitude': 0}}):
            reader.data.return_value = data
            with self.assertRaises(SafeError):
                Service(Config(), reader).call('read_location', {})

    def test_redirect_rejected(self):
        with self.assertRaises(SafeError):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://untrusted.invalid')

    def test_live_transport_mocked_get_endpoint_tls_and_origin(self):
        with tempfile.TemporaryDirectory() as root:
            vin = Path(root) / 'vin'
            token = Path(root) / 'token'
            vin.write_text('AAAAAAAAAAAAAAAAA')
            token.write_text('synthetic-token')
            vin.chmod(0o600)
            token.chmod(0o600)
            config = Config('live-read', True, 'na', str(vin), str(token))
            reader = FleetReader(config)
            response = Mock()
            response.read.return_value = b'{"response":{"charge_state":{"battery_level":72}}}'
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            reader.opener = Mock()
            reader.opener.open.return_value = response
            self.assertEqual(reader.data('charge_state')['charge_state']['battery_level'], 72)
            request = reader.opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), 'GET')
            self.assertTrue(request.full_url.startswith('https://fleet-api.prd.na.vn.cloud.tesla.com/'))
            self.assertTrue(request.full_url.endswith('?endpoints=charge_state'))
            self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
            self.assertEqual(reader.opener.open.call_args.kwargs['timeout'], 10)
            for status in (401, 403, 408, 429, 500):
                reader.opener.open.reset_mock()
                reader.opener.open.side_effect = urllib.error.HTTPError('sensitive-url', status, 'private-body', {}, None)
                with self.assertRaises(SafeError) as caught:
                    reader.data('charge_state')
                self.assertNotIn('sensitive', str(caught.exception))
                self.assertNotIn('private-body', str(caught.exception))
                self.assertEqual(reader.opener.open.call_count, 1)
            with self.assertRaises(SafeError):
                reader.data('wake_up')


class MCPTests(unittest.TestCase):
    def request(self, session, method, params=None):
        return session.handle({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

    def ready(self):
        session = Session(Service(Config()))
        response = self.request(session, 'initialize', {'protocolVersion': '2025-11-25'})
        self.assertEqual(response['result']['protocolVersion'], '2025-11-25')
        session.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        return session

    def test_lifecycle_and_read_command_annotations(self):
        session = Session(Service(Config()))
        self.assertIn('error', self.request(session, 'tools/list'))
        tools = self.request(self.ready(), 'tools/list')['result']['tools']
        self.assertEqual(len(tools), 5)
        self.assertTrue(tools[0]['annotations']['readOnlyHint'])
        self.assertFalse(tools[3]['annotations']['readOnlyHint'])

    def test_tool_errors_and_unexpected_exception_redaction(self):
        session = self.ready()
        for name in ('door_unlock', 'execute_navigation', '<private>'):
            result = self.request(session, 'tools/call', {'name': name})['result']
            self.assertTrue(result['isError'])
            self.assertNotIn(name, json.dumps(result))
        session.service.reader = Mock()
        session.service.reader.data.side_effect = RuntimeError('private-token-and-location')
        result = self.request(session, 'tools/call', {'name': 'read_location'})['result']
        self.assertNotIn('private-token', json.dumps(result))
        self.assertTrue(result['isError'])

    def test_jsonrpc_shape(self):
        session = self.ready()
        self.assertIn('error', session.handle([]))
        self.assertIsNone(session.handle({'jsonrpc': '2.0', 'method': 'notifications/cancelled'}))
        self.assertIn('error', session.handle({'jsonrpc': '2.0', 'id': True, 'method': 'ping'}))

    def test_stdio_subprocess_parse_recovery_and_mock_call(self):
        messages = '\n'.join([json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                          'params': {'protocolVersion': '2025-11-25'}}),
                              json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}),
                              'invalid-json-private',
                              json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                                          'params': {'name': 'read_battery_charging'}})]) + '\n'
        env = dict(os.environ, TESLA_CONNECTOR_MODE='mock', TESLA_CONNECTOR_ALLOW_LIVE_READS='false')
        completed = subprocess.run([sys.executable, '-m', 'tesla_connector.mcp'], input=messages,
                                   text=True, capture_output=True, env=env, timeout=5)
        self.assertEqual(completed.returncode, 0)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[1]['error']['code'], -32700)
        self.assertEqual(json.loads(responses[2]['result']['content'][0]['text'])['battery_percent'], 72)
        self.assertEqual(completed.stderr, '')
        self.assertNotIn('invalid-json-private', completed.stdout)

    def test_oversize_and_nonfinite_messages(self):
        env = dict(os.environ, TESLA_CONNECTOR_MODE='mock')
        completed = subprocess.run([sys.executable, '-m', 'tesla_connector.mcp'], input='x' * 65537,
                                   text=True, capture_output=True, env=env, timeout=5)
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn('xxxx', completed.stderr)
        completed = subprocess.run([sys.executable, '-m', 'tesla_connector.mcp'], input='{"x":NaN}\n',
                                   text=True, capture_output=True, env=env, timeout=5)
        self.assertEqual(json.loads(completed.stdout)['error']['code'], -32700)


if __name__ == '__main__':
    unittest.main()
