"""Offline template consistency; no credentials, configuration writes or network."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesla_connector.live_activation import SIGNER_FIELDS, POLICY_FIELDS, OPTIONAL_POLICY_FIELDS
from tesla_connector.control_catalog import CATALOG
root = Path(__file__).resolve().parents[1]
load = lambda name: json.loads((root / name).read_text())
assert set(load('examples/signer-service.json.example')) == SIGNER_FIELDS
policy = load('examples/control-service.json.example')
assert POLICY_FIELDS <= set(policy) <= POLICY_FIELDS | OPTIONAL_POLICY_FIELDS
assert all(v is False for k,v in policy.items() if k != 'version')
assert CATALOG == load('signer/control-catalog.json')
gateway = load('examples/gateway-config.json.example')
assert gateway['BROKER_URL'].endswith('.invalid/mcp') and gateway['REMOTE_CONTROL_MODE'] == 'mock'
assert set(gateway['required_secret_names']) == {'BROKER_GATEWAY_TOKEN','ACCESS_CLIENT_ID','ACCESS_CLIENT_SECRET'}
for doc in (root / 'docs').glob('*.md'):
    assert doc.read_text().strip()
print('PASS: example schemas, disabled policy, matching catalogs and placeholder gateway configuration')
