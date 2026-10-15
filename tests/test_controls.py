import concurrent.futures
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tesla_connector.controls import ControlIntent,Capabilities,StagedControlAdapter,OwnerControlWorkflow,SPECS as ALL_SPECS
from tesla_connector.commands import ApprovalLedger,MockProxy,canonical
from tesla_connector.storage import PrivateStore,DurableBudget,DurableApprovalLedger
from tesla_connector.service import SafeError
from tesla_connector.mcp import TOOLS

# Legacy staged-adapter tests cover its original sixteen-action contract.
# The expanded catalog has independent validation in Python smoke and Go tests.
BASE_ACTIONS = {'climate_start','climate_stop','set_temperature','charge_start',
'charge_stop','set_charge_limit','set_charging_amps','charge_port_open',
'charge_port_close','navigation_send','lock','unlock','front_trunk','rear_trunk',
'flash_lights','honk_horn'}
SPECS = {k: v for k, v in ALL_SPECS.items() if k in BASE_ACTIONS}

class FailingProxy(MockProxy):
    def send(self,request):self.calls+=1;raise TimeoutError('synthetic-private-details')

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.now=1000.;self.owner='synthetic-owner';self.target='AAAAAAAAAAAAAAAAA'
        self.ledger=ApprovalLedger(clock=lambda:self.now)
        self.scopes=frozenset(('openid','offline_access','vehicle_device_data','vehicle_cmds','vehicle_charging_cmds'))
        self.caps=Capabilities(self.scopes,True,True,True,True,True,True,self.now)
        self.proxy=MockProxy();self.adapter=StagedControlAdapter(self.ledger,transport=self.proxy,clock=lambda:self.now)
    def intent(self,action,args=None):return ControlIntent.build(self.owner,self.target,action,args or {})
    def test_all_command_contracts_are_whitelisted_and_mock_only(self):
        params={'set_temperature':{'celsius':22},'set_charge_limit':{'percent':80},'set_charging_amps':{'amps':16},'navigation_send':{'destination':'Synthetic private destination'}}
        for action,spec in SPECS.items():
            with self.subTest(action=action):
                intent=self.intent(action,params.get(action));intent.validated()
                approval=self.ledger.approve(intent)
                result=self.adapter.submit(intent,approval,'synthetic-access',self.caps)
                self.assertTrue(result['simulated']);self.assertFalse(result['vehicle_execution_verified'])
                self.assertEqual(result['command'],spec.endpoint)
        self.assertEqual(self.proxy.calls,len(SPECS))
    def test_payload_and_destination_redaction(self):
        for action,args,expected in [('set_temperature',{'celsius':22},{'driver_temp':22,'passenger_temp':22}),('set_charge_limit',{'percent':80},{'percent':80}),('set_charging_amps',{'amps':16},{'charging_amps':16}),('front_trunk',{}, {'which_trunk':'front'}),('rear_trunk',{}, {'which_trunk':'rear'})]:
            self.assertEqual(json.loads(self.intent(action,args).payload_json),expected)
        intent=self.intent('navigation_send',{'destination':'Synthetic private destination'})
        self.assertNotIn('Synthetic private destination',json.dumps(intent.preview()))
        self.assertNotIn(self.target,json.dumps(intent.preview()))
        self.assertFalse(intent.preview()['execution_enabled'])
    def test_invalid_inputs_arbitrary_commands_and_paths_rejected(self):
        for action,args in [('set_temperature',{'celsius':True}),('set_temperature',{'celsius':29}),('set_charge_limit',{'percent':49}),('set_charge_limit',{'percent':80.1}),('set_charging_amps',{'amps':0}),('set_charging_amps',{'amps':True}),('navigation_send',{'destination':'private\ntext'}),('lock',{'approval':True}),('wake_up',{}),('../../command/door_unlock',{})]:
            with self.subTest(action=action,args=args),self.assertRaises(SafeError):self.intent(action,args)
    def test_mutated_payload_command_or_action_cannot_reuse_grant(self):
        intent=self.intent('lock');approval=self.ledger.approve(intent)
        altered=ControlIntent(self.owner,self.target,'unlock','door_unlock',b'{}')
        with self.assertRaises(SafeError):self.adapter.submit(altered,approval,'synthetic-access',self.caps)
        with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',self.caps)
        self.assertEqual(self.proxy.calls,0)
        with self.assertRaises(SafeError):ControlIntent(self.owner,self.target,'lock','door_unlock',b'{}').validated()
        with self.assertRaises(SafeError):ControlIntent(self.owner,self.target,'lock','door_lock',b'{"extra":true}').validated()
    def test_missing_scope_pairing_protocol_and_unsupported_hardware_burn_grants(self):
        variants=[Capabilities(),replace(self.caps,pairing_verified=False),replace(self.caps,signing_proxy_verified=False),replace(self.caps,protocol_required=None),replace(self.caps,unsupported_actions=frozenset({'charge_port_close'}))]
        intent=self.intent('charge_port_close')
        for caps in variants:
            approval=self.ledger.approve(intent)
            with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
            with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',self.caps)
        self.assertEqual(self.proxy.calls,0)
    def test_nonpark_actions_accept_absent_gear_and_old_vehicle_observation_once(self):
        params={'set_temperature':{'celsius':20},'set_charge_limit':{'percent':80},'set_charging_amps':{'amps':16},'navigation_send':{'destination':'Synthetic destination'}}
        caps=replace(self.caps,parked=None,observed_at=0)
        actions=[action for action,spec in SPECS.items() if not spec.requires_park]
        self.assertEqual(len(actions),13)
        for action in actions:
            with self.subTest(action=action):
                intent=self.intent(action,params.get(action));approval=self.ledger.approve(intent)
                self.assertEqual(caps.blockers(action,self.now),[])
                result=self.adapter.submit(intent,approval,'synthetic-access',caps)
                self.assertTrue(result['simulated']);self.assertFalse(result['vehicle_execution_verified'])
                with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
        self.assertEqual(self.proxy.calls,13)
    def test_nonpark_state_policy_does_not_extend_exact_approval_expiry(self):
        caps=replace(self.caps,parked=None,observed_at=0)
        intent=self.intent('set_temperature',{'celsius':20});approval=self.ledger.approve(intent,ttl=60)
        self.now+=61
        self.assertEqual(caps.blockers(intent.action,self.now),[])
        with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
        with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
        self.assertEqual(self.proxy.calls,0)
    def test_park_actions_require_fresh_explicit_park_and_burn_refused_approvals(self):
        actions={action for action,spec in SPECS.items() if spec.requires_park}
        self.assertEqual(actions,{'honk_horn','flash_lights','charge_port_open'})
        invalid=(replace(self.caps,parked=None),replace(self.caps,parked=False),replace(self.caps,observed_at=self.now-61),replace(self.caps,observed_at=self.now+1))
        for action in sorted(actions):
            intent=self.intent(action)
            for caps in invalid:
                with self.subTest(action=action,parked=caps.parked,observed_at=caps.observed_at):
                    approval=self.ledger.approve(intent)
                    with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
                    with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',self.caps)
            approval=self.ledger.approve(intent)
            self.assertTrue(self.adapter.submit(intent,approval,'synthetic-access',replace(self.caps,observed_at=self.now-60))['simulated'])
        self.assertEqual(self.proxy.calls,3)
    def test_cable_and_motorized_hardware_checks_are_action_specific(self):
        params={'set_temperature':{'celsius':20},'set_charge_limit':{'percent':80},'set_charging_amps':{'amps':16},'navigation_send':{'destination':'Synthetic destination'}}
        caps=replace(self.caps,cable_connected=None,motorized_charge_port=None)
        for action,spec in SPECS.items():
            with self.subTest(action=action):
                intent=self.intent(action,params.get(action));approval=self.ledger.approve(intent)
                if action in ('charge_start','charge_port_close'):
                    expected='charging-cable-not-verified' if action=='charge_start' else 'motorized-charge-port-not-verified'
                    self.assertIn(expected,caps.blockers(action,self.now))
                    with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',caps)
                    with self.assertRaises(SafeError):self.adapter.submit(intent,approval,'synthetic-access',self.caps)
                else:
                    self.assertFalse(spec.needs_cable or spec.motorized_port)
                    self.assertTrue(self.adapter.submit(intent,approval,'synthetic-access',caps)['simulated'])
        self.assertEqual(self.proxy.calls,14)
    def test_current_read_grant_blocks_every_control(self):
        caps=Capabilities(frozenset(('offline_access','openid','vehicle_device_data')),observed_at=self.now)
        for action in SPECS:self.assertIn('required-scope-not-granted',caps.blockers(action,self.now))
    def test_cable_and_motorized_port_detection_are_fail_closed(self):
        caps=Capabilities.from_verified_metadata(self.scopes,{'total_number_of_keys':2},{'parked':True},self.now)
        self.assertFalse(caps.pairing_verified);self.assertIsNone(caps.protocol_required)
        self.assertIn('charging-cable-not-verified',caps.blockers('charge_start',self.now))
        self.assertIn('motorized-charge-port-not-verified',caps.blockers('charge_port_close',self.now))
    def test_owner_review_and_exact_bound_one_use_confirmation(self):
        workflow=OwnerControlWorkflow(self.owner,self.target,self.ledger,clock=lambda:self.now)
        reference,public=workflow.prepare('navigation_send',{'destination':'Synthetic private destination'})
        self.assertNotIn('Synthetic private destination',json.dumps(public))
        self.assertIn('Synthetic private destination',json.dumps(workflow.owner_review(reference)))
        intent=workflow.pending[reference][0]
        with self.assertRaises(SafeError):workflow.confirm(reference,intent.binding(),owner='different-owner')
        approved,ticket=workflow.confirm(reference,intent.binding(),owner=self.owner)
        self.assertEqual(approved,intent);self.ledger.consume(ticket,intent)
        with self.assertRaises(SafeError):self.ledger.consume(ticket,intent)
        with self.assertRaises(SafeError):workflow.confirm(reference,intent.binding(),owner=self.owner)
    def test_changed_or_expired_review_cannot_approve(self):
        workflow=OwnerControlWorkflow(self.owner,self.target,self.ledger,clock=lambda:self.now)
        reference,_=workflow.prepare('lock',{})
        with self.assertRaises(SafeError):workflow.confirm(reference,b'x'*32,owner=self.owner)
        reference,_=workflow.prepare('unlock',{});self.now+=301
        with self.assertRaises(SafeError):workflow.owner_review(reference)
    def test_production_kill_switch_has_no_network_or_spending(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700);budget=DurableBudget(PrivateStore(tmp),'synthetic-owner');budget.configure_total(100000)
            intent=self.intent('lock');ticket=self.ledger.approve(intent)
            with patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('forbidden')):
                with self.assertRaisesRegex(SafeError,'disabled'):StagedControlAdapter(self.ledger,budget,clock=lambda:self.now).submit(intent,ticket,'synthetic-access',self.caps)
            self.assertEqual(budget.total_status()['reserved_microdollars'],0)
        class LiveLike:
            simulated=False
        with self.assertRaises(SafeError):StagedControlAdapter(self.ledger,transport=LiveLike())
    def test_no_mcp_approval_or_execute_surface_is_added(self):
        self.assertFalse(any('approve' in t['name'] or 'execute' in t['name'] for t in TOOLS))
        self.assertEqual(len(TOOLS),5)
    def test_timeout_requires_new_action_approval_and_no_retry(self):
        proxy=FailingProxy();adapter=StagedControlAdapter(self.ledger,transport=proxy,clock=lambda:self.now)
        intent=self.intent('climate_start');approval=self.ledger.approve(intent)
        with self.assertRaises(SafeError) as caught:adapter.submit(intent,approval,'synthetic-access',self.caps)
        self.assertNotIn('private-details',str(caught.exception))
        with self.assertRaises(SafeError):adapter.submit(intent,approval,'synthetic-access',self.caps)
        self.assertEqual(proxy.calls,1)
    def test_durable_approval_and_existing_total_cap_for_mock_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700);store=PrivateStore(tmp);ledger=DurableApprovalLedger(store);budget=DurableBudget(store,self.owner);budget.configure_total(1000)
            intent=self.intent('climate_stop');approval=ledger.approve(intent)
            adapter=StagedControlAdapter(ledger,budget,self.proxy,clock=lambda:self.now)
            self.assertTrue(adapter.submit(intent,approval,'synthetic-access',self.caps)['simulated'])
            self.assertEqual(budget.total_status()['reserved_microdollars'],1000)
            approval=ledger.approve(intent)
            with self.assertRaises(SafeError):adapter.submit(intent,approval,'synthetic-access',self.caps)
            with self.assertRaises(SafeError):adapter.submit(intent,approval,'synthetic-access',self.caps)
            self.assertEqual(self.proxy.calls,1)
