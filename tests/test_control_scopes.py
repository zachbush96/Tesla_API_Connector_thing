import unittest
from tesla_connector.oauth import token_response,ALLOWED_SCOPES
from tesla_connector.service import SafeError
class ControlScopeTests(unittest.TestCase):
 def response(self,scope):return {'access_token':'synthetic-access','refresh_token':'synthetic-refresh','expires_in':3600,'scope':scope,'token_type':'Bearer'}
 def test_command_charging_supported_only_when_explicitly_requested(self):
  requested={'openid','offline_access','vehicle_device_data','vehicle_cmds','vehicle_charging_cmds'}
  self.assertTrue(requested<=ALLOWED_SCOPES)
  self.assertEqual(token_response(self.response(' '.join(sorted(requested))),requested,100).scopes,frozenset(requested))
 def test_read_consent_cannot_gain_command_charging_or_location(self):
  read={'openid','offline_access','vehicle_device_data'}
  for scope in ('vehicle_cmds','vehicle_charging_cmds','vehicle_location'):
   with self.assertRaises(SafeError):token_response(self.response(' '.join(sorted(read|{scope}))),read,100)
