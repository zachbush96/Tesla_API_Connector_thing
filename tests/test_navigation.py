import json
import unittest
from unittest.mock import patch
from tesla_connector.commands import ApprovalLedger, CommandAdapter, Intent, MockProxy, canonical
from tesla_connector.service import SafeError, command_plan, navigation_payload


class NavigationTests(unittest.TestCase):
    def test_official_address_share_contract(self):
        with patch('tesla_connector.service.time.time', return_value=1700000000):
            command, payload = command_plan('preview_navigation', {'destination': 'Synthetic test place'})
        self.assertEqual(command, 'navigation_request')
        self.assertEqual(payload, {'type': 'share_ext_content_raw',
            'value': {'android.intent.ACTION': 'android.intent.action.SEND',
                      'android.intent.TYPE': 'text/plain', 'android.intent.TEXT': 'Synthetic test place',
                      'android.intent.extra.TEXT': 'Synthetic test place'},
            'locale': 'en-US', 'timestamp_ms': '1700000000000'})

    def test_plain_text_validation(self):
        for destination in (True, None, 22, '', ' ', 'x' * 301, 'place\ncommand', 'place\x00', 'place\x7f'):
            with self.assertRaises(SafeError):
                navigation_payload(destination)

    def test_unicode_scalar_character_limit_matches_schema(self):
        for destination in ('\U0001F697'*151, '\U0001F697'*300):
            self.assertEqual(navigation_payload(destination)['value']['android.intent.TEXT'], destination)
        with self.assertRaises(SafeError):
            navigation_payload('\U0001F697'*301)

    def test_surrogate_code_units_refused_before_proposal_or_transport(self):
        from tesla_connector.controls import ControlIntent
        for destination in ('\ud800', '\udfff', 'Synthetic \udc00 destination', '\ud83d\ude97'):
            with self.assertRaises(SafeError):
                navigation_payload(destination)
            with self.assertRaises(SafeError):
                Intent.build('synthetic-owner','AAAAAAAAAAAAAAAAA','preview_navigation',{'destination':destination})
            with self.assertRaises(SafeError):
                ControlIntent.build('synthetic-owner','AAAAAAAAAAAAAAAAA','navigation_send',{'destination':destination})

    def test_timestamp_bound_and_no_regeneration_during_submission(self):
        intent = Intent.build('synthetic-owner', 'AAAAAAAAAAAAAAAAA', 'preview_navigation', {'destination': 'Synthetic test place'})
        ledger = ApprovalLedger()
        ticket = ledger.approve(intent)
        with patch('tesla_connector.service.time.time', return_value=1900000000):
            self.assertEqual(intent.validated().payload_json, intent.payload_json)
            self.assertTrue(CommandAdapter(ledger, MockProxy()).submit(intent, ticket, 'synthetic-token')['simulated'])

    def test_tampered_share_fields_and_old_gps_command_refused(self):
        intent = Intent.build('synthetic-owner', 'AAAAAAAAAAAAAAAAA', 'preview_navigation', {'destination': 'Synthetic test place'})
        for key, value in (('type', 'share_ext'), ('locale', 'unapproved'), ('timestamp_ms', 'not-a-timestamp')):
            payload = json.loads(intent.payload_json)
            payload[key] = value
            with self.assertRaises(SafeError):
                Intent(intent.principal, intent.target, intent.command, canonical(payload)).validated()
        payload = json.loads(intent.payload_json)
        payload['value']['android.intent.extra.TEXT'] = 'Different destination'
        with self.assertRaises(SafeError):
            Intent(intent.principal, intent.target, intent.command, canonical(payload)).validated()
        with self.assertRaises(SafeError):
            Intent(intent.principal, intent.target, 'navigation_gps_request', canonical({'lat': 0, 'lon': 0, 'order': 1})).validated()

    def test_navigation_approval_binds_destination_and_timestamp(self):
        original = Intent.build('synthetic-owner', 'AAAAAAAAAAAAAAAAA', 'preview_navigation', {'destination': 'Synthetic test place'})
        payload = json.loads(original.payload_json)
        payload['timestamp_ms'] = str(int(payload['timestamp_ms']) + 1)
        altered = Intent(original.principal, original.target, original.command, canonical(payload))
        ledger = ApprovalLedger()
        ticket = ledger.approve(original)
        proxy = MockProxy()
        with self.assertRaises(SafeError):
            CommandAdapter(ledger, proxy).submit(altered, ticket, 'synthetic-token')
        self.assertEqual(proxy.calls, 0)


if __name__ == '__main__':
    unittest.main()
