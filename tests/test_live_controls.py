"""Focused live-boundary tests with fake Fleet and local signer transports only."""
import concurrent.futures
from email.message import Message
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest

from tesla_connector.broker import Broker
from tesla_connector.controls import ControlIntent, SPECS, canonical
from tesla_connector.http_mock import VerifiedIdentity
from tesla_connector.live_controls import FleetCapabilityReader, SignerBridge, SDK_COMMIT, derive_bridge_token, wire_intent
from tesla_connector.oauth import OAuthClient, MemoryVault, Tokens
from tesla_connector.remote_controls import RemoteOperations, SignerLiveExecutor, SignerPairingVerifier
from tesla_connector.service import SafeError
from tesla_connector.storage import PrivateStore, DurableBudget

OWNER = 'synthetic-owner'
TARGET = 'AAAAAAAAAAAAAAAAA'
KEY = 'a' * 64
SIGNER_TOKEN = 'synthetic-local-capability-' + 's' * 48


class Response:
    def __init__(self, value, status=200, raw=None):
        self.raw = canonical(value) if raw is None else raw
        self.status = status
        self.headers = Message()
        self.headers['Content-Type'] = 'application/json'
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, n): return self.raw[:n]


class FakeFleet:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.online = True
        self.gear = None
        self.speed = None
        self.timestamp_delta = 0
        self.cable = 'SAE'
        self.motorized = True
        self.fault = None
        self.lock = threading.Lock()
    def open(self, request, timeout):
        with self.lock:
            if '/fleet_status' in request.full_url:
                kind = 'fleet_status'
                value = {'response':{'key_paired_vins':[TARGET], 'unpaired_vins':[],
                    'vehicle_info':{TARGET:{'vehicle_command_protocol_required':True}}}}
            elif '/vehicle_data?' in request.full_url:
                kind = 'vehicle_data'
                stamp = int((self.clock() + self.timestamp_delta) * 1000)
                value = {'response':{'vin':TARGET, 'state':'online',
                    'drive_state':{'timestamp':stamp, 'shift_state':self.gear, 'speed':self.speed},
                    'charge_state':{'timestamp':stamp, 'conn_charge_cable':self.cable, 'charging_state':'Stopped'},
                    'vehicle_config':{'timestamp':stamp, 'motorized_charge_port':self.motorized}}}
            else:
                kind = 'vehicle'
                value = {'response':{'vin':TARGET, 'state':'online' if self.online else 'asleep'}}
            self.calls.append(kind)
            if self.fault is not None: raise self.fault
            return Response(value)


class FakeSigner:
    """Exercises the actual Python callback auth, exact journal and client parser."""
    def __init__(self, broker, clock):
        self.broker, self.clock = broker, clock
        self.requests = 0
        self.outbound = []
        self.override = None
    def callback(self, name, value):
        headers = {'host':'127.0.0.1:8765', 'authorization':'Bearer ' + derive_bridge_token(SIGNER_TOKEN), 'content-type':'application/json'}
        status, _, result = self.broker.handle('POST', '/internal/signer/' + name, headers, canonical(value))
        if status != 200: raise SafeError('Synthetic callback refused')
        return result
    def open(self, request, timeout):
        self.requests += 1
        value = json.loads(request.data)
        operation, intent = value['operation_id'], value['intent']
        mode = 'verify_pairing' if request.full_url.endswith('/verify_pairing') else 'execute'
        binding = hashlib.sha256(canonical(intent)).hexdigest()
        claim = self.callback('claim', {'operation_id':operation, 'intent':intent, 'mode':mode, 'signing_key_sha256':KEY})
        if not claim['facts']['protocol_known'] or (mode=='verify_pairing' and not claim['facts']['awake']): raise SafeError('Synthetic facts unavailable')
        common = {'operation_id':operation, 'binding_sha256':binding, 'signing_key_sha256':KEY, 'sdk_commit':SDK_COMMIT}
        kinds = ['handshake'] if mode == 'verify_pairing' else ['state_handshake','state_query','command'] if SPECS[intent['action']].requires_park else ['navigation'] if intent['action']=='navigation_send' else ['handshake','command']
        for attempt, kind in enumerate(kinds, 1):
            self.callback('reserve', {'operation_id':operation, 'binding_sha256':binding, 'category':'commands', 'kind':kind, 'attempt':attempt})
            self.outbound.append(kind)  # A fake outbound attempt occurs only AFTER durable reserve.
            if kind == 'state_query':
                self.callback('state', {**common, 'parked':True, 'awake':True, 'observed_unix_ms':int(self.clock()*1000)})
        if mode == 'verify_pairing':
            self.callback('pairing', {**common, 'pairing_verified':True})
            result = {'pairing_verified':True, 'execution_enabled':False, 'vehicle_execution_verified':False,
                'sdk_commit':SDK_COMMIT, 'fleet_network_requests':1, 'gross_reserved_microdollars':1000}
        else:
            result = {'action':intent['action'], 'simulated':False, 'submitted':True, 'accepted':True,
                'vehicle_execution_verified':False, 'execution_enabled':True, 'sdk_commit':SDK_COMMIT,
                'fleet_network_requests':len(kinds), 'gross_reserved_microdollars':1000*len(kinds)}
        if self.override: result.update(self.override)
        return Response(result)


class LiveControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        Path(self.temp.name).chmod(0o700)
        self.now = 1700000000.
        self.store = PrivateStore(self.temp.name, clock=lambda:self.now)
        self.budget = DurableBudget(self.store, OWNER)
        self.budget.configure_total(100000)
        self.vault = MemoryVault(OWNER)
        self.vault.save(Tokens('synthetic-current-access', 'synthetic-current-refresh', self.now + 3600,
            frozenset(('openid','offline_access','vehicle_device_data','vehicle_cmds','vehicle_charging_cmds'))))
        self.oauth = OAuthClient(self.store, OWNER, 'synthetic-client', 'synthetic-client-secret', vault=self.vault)
        with self.store.transaction() as db:
            db.execute('INSERT INTO refresh_state VALUES(?,?,?)', (self.budget.owner,'ready',4))
        self.fleet = FakeFleet(lambda:self.now)
        self.reader = FleetCapabilityReader(TARGET, self.budget, opener=self.fleet, clock=lambda:self.now)
        self.bridge = SignerBridge(OWNER,TARGET,self.oauth,self.budget,self.reader,KEY,execution_enabled=True,pairing_diagnostic_enabled=True)
        self.broker = Broker(OWNER,'o'*64,'m'*64,signer_bridge=self.bridge,signer_bridge_token=derive_bridge_token(SIGNER_TOKEN))
        self.signer = FakeSigner(self.broker,lambda:self.now)
        self.executor = object.__new__(SignerLiveExecutor)
        self.executor._token=SIGNER_TOKEN;self.executor._opener=self.signer
        self.executor.bridge=self.bridge;self.executor.execution_enabled=True
        self.verifier = object.__new__(SignerPairingVerifier)
        self.verifier._token=SIGNER_TOKEN;self.verifier._opener=self.signer
        self.verifier.bridge=self.bridge;self.verifier.diagnostic_enabled=True;self.verifier.execution_enabled=False

    def paired(self): return self.verifier.verify()

    def arm(self, action='lock', parameters=None, maximum=None):
        intent=ControlIntent.build(OWNER,TARGET,action,parameters or {})
        self.bridge.grants.arm(intent, maximum if maximum is not None else 6000 if action in ('lock','unlock','front_trunk','rear_trunk') else 5000)
        return intent

    def registered(self, action='flash_lights', operation='b'*32):
        intent = ControlIntent.build(OWNER,TARGET,action,{'destination':'Synthetic destination'} if action=='navigation_send' else {})
        self.bridge.grants.arm(intent,6000 if action in ('lock','unlock','front_trunk','rear_trunk') else 5000)
        value = wire_intent(intent)
        self.bridge.register(operation,value,'execute')
        claim={'operation_id':operation,'intent':value,'mode':'execute','signing_key_sha256':KEY}
        return operation, value, hashlib.sha256(canonical(value)).hexdigest(), claim

    def test_pairing_uses_one_fresh_nonphysical_handshake_and_binds_current_key(self):
        result = self.paired()
        self.assertTrue(result['pairing_verified'])
        self.assertFalse(result['vehicle_execution_verified'])
        self.assertEqual(self.fleet.calls,['fleet_status','vehicle'])
        self.assertEqual(self.signer.outbound,['handshake'])
        self.assertEqual(result['total_gross_reserved_microdollars'],1000)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],1000)
        replacement = SignerBridge(OWNER,TARGET,self.oauth,self.budget,self.reader,'c'*64,execution_enabled=True)
        old = self.executor.bridge;self.executor.bridge=replacement
        with self.assertRaises(SafeError):self.executor.execute(ControlIntent.build(OWNER,TARGET,'lock',{}),'c'*32)
        self.executor.bridge=old
        self.assertEqual(len(self.fleet.calls),2)

    def test_public_live_execution_retains_owner_exact_binding_replay_and_costs(self):
        self.paired()
        self.arm('lock')
        operations=RemoteOperations(OWNER,TARGET,executor=self.executor)
        owner=VerifiedIdentity(OWNER)
        preview=operations.prepare(owner,'lock',{})
        self.assertFalse(preview['simulated'])
        self.assertEqual(preview['estimated_gross_reservation_microdollars'],2000)
        with self.assertRaises(SafeError):operations.execute(VerifiedIdentity('other'),preview['operation_id'],expected_control_mode='live')
        result=operations.execute(owner,preview['operation_id'],expected_control_mode='live')
        self.assertTrue(result['submitted'] and result['accepted'])
        self.assertFalse(result['vehicle_execution_verified'])
        self.assertEqual(result['total_gross_reserved_microdollars'],2000)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],3000)
        with self.assertRaises(SafeError):operations.execute(owner,preview['operation_id'],expected_control_mode='live')
        self.assertEqual(self.signer.requests,2)
        self.assertTrue('synthetic-current-access' not in json.dumps(result))

    def test_no_physical_or_diagnostic_calls_when_disabled(self):
        self.executor.execution_enabled=False
        self.verifier.diagnostic_enabled=False
        with self.assertRaises(SafeError):self.executor.execute(ControlIntent.build(OWNER,TARGET,'lock',{}),'b'*32)
        with self.assertRaises(SafeError):self.verifier.verify()
        self.assertEqual(self.signer.requests,0)
        self.assertEqual(self.fleet.calls,[])
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],0)

    def test_missing_pairing_and_missing_scope_fail_before_fleet_requests(self):
        self.arm('lock')
        with self.assertRaises(SafeError):self.executor.execute(ControlIntent.build(OWNER,TARGET,'lock',{}),'b'*32)
        self.assertEqual(self.fleet.calls,[])
        self.assertEqual(self.signer.outbound,[])
        tokens=self.vault.load()
        self.vault.save(Tokens(tokens.access_token,tokens.refresh_token,tokens.expires_at,frozenset(('openid','offline_access','vehicle_device_data'))))
        with self.assertRaises(SafeError):self.verifier.verify()
        self.assertEqual(self.fleet.calls,[])
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],0)

    def test_unregistered_changed_key_target_duplicate_and_public_credentials_refused(self):
        raw=canonical({'operation_id':'b'*32,'intent':{'version':1,'principal':OWNER,'target':TARGET,'action':'verify_pairing'},'mode':'verify_pairing','signing_key_sha256':KEY})
        headers={'host':'127.0.0.1:8765','content-type':'application/json','authorization':'Bearer '+derive_bridge_token(SIGNER_TOKEN)}
        for changed in ({}, {'host':'connector.example.invalid'}, {'authorization':'Bearer '+'m'*64}, {'origin':'https://connector.example.invalid'}):
            status,_,body=self.broker.handle('POST','/internal/signer/claim',{**headers,**changed},raw)
            self.assertEqual(status,403)
            self.assertTrue('bearer' not in body)
        status,_,_=self.broker.handle('POST','/internal/signer/claim?x=1',headers,raw)
        self.assertEqual(status,403)
        status,_=self.bridge.handle('/internal/signer/claim',b'{"operation_id":"x","operation_id":"y"}')
        self.assertEqual(status,403)
        self.assertEqual(self.fleet.calls,[])

    def test_claim_is_durable_single_use_even_concurrent_and_after_recomposition(self):
        self.paired()
        operation,_,_,claim=self.registered()
        def attempt(_):
            try:self.bridge.claim(claim);return True
            except SafeError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(attempt,range(16)))
        self.assertEqual(sum(results),1)
        self.assertEqual(self.fleet.calls.count('vehicle_data'),1)
        replacement=SignerBridge(OWNER,TARGET,self.oauth,self.budget,self.reader,KEY,execution_enabled=True,pairing_diagnostic_enabled=True)
        with self.assertRaises(SafeError):replacement.claim(claim)
        with self.assertRaises(SafeError):replacement.register(operation,claim['intent'],'execute')

    def test_action_reservation_needs_explicit_fresh_sdk_state_and_expected_sequence(self):
        self.paired();operation,_,binding,claim=self.registered('flash_lights')
        facts=self.bridge.claim(claim)['facts']
        self.assertFalse(facts['parked'])  # REST null gear never authorizes physical control.
        def reserve(kind,attempt):return self.bridge.reserve({'operation_id':operation,'binding_sha256':binding,'category':'commands','kind':kind,'attempt':attempt})
        with self.assertRaises(SafeError):reserve('command',1)
        reserve('state_handshake',1);reserve('state_query',2)
        with self.assertRaises(SafeError):reserve('command',3)
        receipt={'operation_id':operation,'binding_sha256':binding,'signing_key_sha256':KEY,'parked':True,'awake':True,'observed_unix_ms':int(self.now*1000),'sdk_commit':SDK_COMMIT}
        for change in ({'parked':False},{'parked':1},{'observed_unix_ms':int((self.now-61)*1000)},{'signing_key_sha256':'c'*64}):
            with self.assertRaises(SafeError):self.bridge.state({**receipt,**change})
        self.bridge.state(receipt);reserve('command',3)
        with self.assertRaises(SafeError):reserve('command',4)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],6000)

    def test_lifetime_cap_failure_reserves_before_attempt_never_refunds(self):
        self.paired();intent=self.arm('flash_lights');self.budget.configure_total(6000)
        callback=self.signer.callback
        def concurrent_spend(name,value):
            result=callback(name,value)
            if name=='reserve' and value['kind']=='state_query':self.budget.reserve('commands')
            return result
        self.signer.callback=concurrent_spend
        with self.assertRaises(SafeError):self.executor.execute(intent,'b'*32)
        self.assertEqual(self.signer.outbound,['handshake','state_handshake','state_query'])
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],6000)
        with self.assertRaises(SafeError):self.budget.reserve('commands')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],6000)

    def test_replaced_generation_or_expiry_blocks_remaining_attempts_without_refresh(self):
        self.paired();operation,_,binding,claim=self.registered()
        self.bridge.claim(claim)
        with self.store.transaction() as db:
            db.execute('UPDATE refresh_state SET generation=generation+1 WHERE owner_hash=?',(self.budget.owner,))
        with self.assertRaises(SafeError):self.bridge.reserve({'operation_id':operation,'binding_sha256':binding,'category':'commands','kind':'state_handshake','attempt':1})
        self.assertEqual(self.signer.outbound,['handshake'])
        self.now+=120
        with self.assertRaises(SafeError):self.bridge.claim(claim)

    def test_consent_replaced_during_free_probe_stops_next_request_before_spending(self):
        self.paired()
        original=self.fleet.open
        def replace_consent(request,timeout):
            result=original(request,timeout)
            if self.fleet.calls[-1]=='fleet_status':
                with self.store.transaction() as db:
                    db.execute('UPDATE refresh_state SET generation=generation+1 WHERE owner_hash=?',(self.budget.owner,))
            return result
        self.fleet.open=replace_consent
        with self.assertRaises(SafeError):self.executor.execute(self.arm('lock'),'b'*32)
        self.assertEqual(self.fleet.calls,['fleet_status','vehicle','fleet_status'])
        self.assertEqual(self.signer.outbound,['handshake'])
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],1000)

    def test_park_facts_reject_stale_future_nonpark_and_movement(self):
        auth=self.oauth.authorization(('vehicle_cmds','vehicle_device_data'))
        for delta,gear,speed in [(-61,None,None),(1,None,None),(0,'D',0),(0,'P',5),(0,'P',True),(0,'P','0')]:
            self.fleet.timestamp_delta=delta;self.fleet.gear=gear;self.fleet.speed=speed
            with self.assertRaises(SafeError):self.reader.observe(auth,'flash_lights')
        self.fleet.timestamp_delta=0;self.fleet.gear=None;self.fleet.speed=0
        facts=self.reader.observe(auth,'flash_lights')
        self.assertFalse(facts['parked'])
        self.assertEqual(facts['drive_observed_unix_ms'],int(self.now*1000))
        self.assertEqual(self.signer.outbound,[])

    def test_untrusted_signer_success_or_private_transport_error_never_leaks_or_retries(self):
        self.paired();self.signer.override={'vehicle_execution_verified':True}
        with self.assertRaises(SafeError) as result:self.executor.execute(self.arm('lock'),'b'*32)
        self.assertTrue('synthetic-current-access' not in str(result.exception))
        self.assertEqual(self.signer.requests,2)
        self.fleet.fault=RuntimeError('synthetic-private-marker')
        with self.assertRaises(SafeError) as result:self.executor.execute(ControlIntent.build(OWNER,TARGET,'lock',{}),'c'*32)
        self.assertTrue('synthetic-private-marker' not in str(result.exception))
        self.assertEqual(self.signer.requests,2)
