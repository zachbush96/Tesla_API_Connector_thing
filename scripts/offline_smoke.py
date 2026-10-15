"""Exercise the stdio connector without any network or local credential access."""
import json
from pathlib import Path
import socket
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def denied(*args, **kwargs):
    raise AssertionError('Network is forbidden in the offline smoke check')
socket.socket.connect = denied
socket.create_connection = denied
from tesla_connector.keychain import MacKeychain
MacKeychain.operation = denied
from tesla_connector.mcp import Session
from tesla_connector.service import Config, Service
from tesla_connector.control_catalog import CATALOG
from tesla_connector.controls import ControlIntent
from tesla_connector.commands import ApprovalLedger

session = Session(Service(Config()))
def rpc(method, params=None, ident=1):
    return session.handle({'jsonrpc':'2.0', 'id':ident, 'method':method, 'params':params or {}})
assert rpc('initialize', {'protocolVersion':'2025-11-25'})['result']
session.handle({'jsonrpc':'2.0','method':'notifications/initialized'})
assert len(rpc('tools/list')['result']['tools']) == 5
battery = json.loads(rpc('tools/call', {'name':'read_battery_charging','arguments':{}})['result']['content'][0]['text'])
assert battery['mode'] == 'mock' and battery['battery_percent'] == 72
preview = json.loads(rpc('tools/call', {'name':'preview_temperature','arguments':{'celsius':21}})['result']['content'][0]['text'])
assert preview['dry_run'] is True and preview['executed'] is False
assert rpc('tools/call', {'name':'execute_control','arguments':{}})['result']['isError'] is True
assert len(CATALOG) == 43
intent = ControlIntent.build('synthetic-owner','A'*17,'set_temperature',{'celsius':21})
ledger = ApprovalLedger()
ticket = ledger.approve(intent)
ledger.consume(ticket, intent)
try:
    ledger.consume(ticket, intent)
except Exception:
    pass
else:
    raise AssertionError('Consumed approval was replayed')
print('PASS: mock MCP, filtered read, preview, unknown execution refusal, catalog, single-use approval; network/Keychain denied')
