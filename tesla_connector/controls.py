"""Staged owner-confirmed controls. Production execution is permanently disabled.

No network, grants, keys or vehicle capability probes are performed here. The
existing official proxy request/approval adapter is reused only with test doubles.
"""
from dataclasses import dataclass
import hashlib
import json
import re
import secrets
import time
from .commands import canonical,CommandAdapter,DisabledNetwork,MockProxy
from .service import SafeError,arguments,number,navigation_payload

@dataclass(frozen=True)
class ControlSpec:
    endpoint:str
    scope:str
    fields:tuple=()
    effect:str=''
    motorized_port:bool=False
    needs_cable:bool=False
    requires_park:bool=False
    required_facts:tuple=()

# Exact Fleet API/proxy paths; no raw path, wake, drive-start, erasure or key tools.
SPECS={
 'climate_start':ControlSpec('auto_conditioning_start','vehicle_cmds',effect='Start climate preconditioning',requires_park=False),
 'climate_stop':ControlSpec('auto_conditioning_stop','vehicle_cmds',effect='Stop climate preconditioning',requires_park=False),
 'set_temperature':ControlSpec('set_temps','vehicle_cmds',('celsius',),'Set driver and passenger temperature',requires_park=False),
 'charge_start':ControlSpec('charge_start','vehicle_charging_cmds',effect='Start charging',needs_cable=True),
 'charge_stop':ControlSpec('charge_stop','vehicle_charging_cmds',effect='Stop charging'),
 'set_charge_limit':ControlSpec('set_charge_limit','vehicle_charging_cmds',('percent',),'Set charge percentage limit'),
 'set_charging_amps':ControlSpec('set_charging_amps','vehicle_charging_cmds',('amps',),'Set charging current'),
 'charge_port_open':ControlSpec('charge_port_door_open','vehicle_charging_cmds',effect='Open charge port',requires_park=True),
 'charge_port_close':ControlSpec('charge_port_door_close','vehicle_charging_cmds',effect='Close charge port',motorized_port=True),
 'navigation_send':ControlSpec('navigation_request','vehicle_cmds',('destination',),'Send destination to navigation',requires_park=False),
 'lock':ControlSpec('door_lock','vehicle_cmds',effect='Lock vehicle'),
 'unlock':ControlSpec('door_unlock','vehicle_cmds',effect='Unlock vehicle'),
 'front_trunk':ControlSpec('actuate_trunk','vehicle_cmds',effect='Actuate front trunk; do not assume powered closing'),
 'rear_trunk':ControlSpec('actuate_trunk','vehicle_cmds',effect='Actuate rear trunk; direction depends on hardware/state'),
 'flash_lights':ControlSpec('flash_lights','vehicle_cmds',effect='Briefly flash headlights',requires_park=True),
 'honk_horn':ControlSpec('honk_horn','vehicle_cmds',effect='Sound horn',requires_park=True),
}
from .control_catalog import CATALOG,parameters as typed_parameters,redacted
for _action,_entry in CATALOG.items():
 if _action not in SPECS:
  SPECS[_action]=ControlSpec(_entry['command'],_entry['scope'],tuple(_entry['properties']),_entry['effect'],requires_park=_entry['requires_park'],required_facts=tuple(_entry['required_facts']))
 else:
  from dataclasses import replace
  SPECS[_action]=replace(SPECS[_action],required_facts=tuple(_entry['required_facts']))
_ADDITIONAL=set(CATALOG)-{'lock', 'honk_horn', 'rear_trunk', 'climate_stop', 'unlock', 'set_charging_amps', 'set_temperature', 'front_trunk', 'navigation_send', 'charge_port_open', 'charge_start', 'charge_stop', 'climate_start', 'charge_port_close', 'flash_lights', 'set_charge_limit'}


def payload(action,args,timestamp=None):
    spec=SPECS.get(action)
    if spec is None:raise SafeError('Control not supported')
    arguments(args,spec.fields)
    if action in _ADDITIONAL:
        return {**typed_parameters(action,args),**CATALOG[action].get('fixed_payload',{})}
    if action=='set_temperature':
        value=number(args['celsius'],15,28)
        return {'driver_temp':value,'passenger_temp':value}
    if action=='set_charge_limit':
        value=args['percent']
        if type(value)is not int or not 50<=value<=100:raise SafeError('Charge limit must be an integer from 50 to 100')
        return {'percent':value}
    if action=='set_charging_amps':
        value=args['amps']
        if type(value)is not int or not 1<=value<=48:raise SafeError('Charging current must be an integer from 1 to 48')
        return {'charging_amps':value}
    if action=='navigation_send':return navigation_payload(args['destination'],timestamp)
    if action in ('front_trunk','rear_trunk'):return {'which_trunk':'front' if action=='front_trunk' else 'rear'}
    return {}


@dataclass(frozen=True,repr=False)
class ControlIntent:
    principal:str
    target:str
    action:str
    command:str
    payload_json:bytes

    @classmethod
    def build(cls,principal,target,action,args):
        if not isinstance(principal,str) or not principal or len(principal)>256 or not isinstance(target,str) or not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}',target):
            raise SafeError('Trusted control owner and vehicle required')
        built=payload(action,args)
        return cls(principal,target,action,SPECS[action].endpoint,canonical(built))

    def validated(self):
        try:
            spec=SPECS[self.action]
            if spec.endpoint!=self.command:raise SafeError('Control path mismatch')
            data=json.loads(self.payload_json)
            args={}
            timestamp=None
            if self.action=='set_temperature':
                if set(data)!={'driver_temp','passenger_temp'} or data['driver_temp']!=data['passenger_temp']:raise SafeError('Control payload mismatch')
                args={'celsius':data['driver_temp']}
            elif self.action=='set_charge_limit':args={'percent':data['percent']}
            elif self.action=='set_charging_amps':args={'amps':data['charging_amps']}
            elif self.action=='navigation_send':
                args={'destination':data['value']['android.intent.TEXT']};timestamp=data['timestamp_ms']
            elif self.action in _ADDITIONAL:args={k:data[k]for k in SPECS[self.action].fields}
            # Validate trusted identity using the existing strict constructor.
            if not isinstance(self.principal,str) or not self.principal or len(self.principal)>256 or not isinstance(self.target,str) or not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}',self.target):raise SafeError('Invalid trusted control identity')
            if canonical(payload(self.action,args,timestamp))!=self.payload_json:raise SafeError('Noncanonical control payload')
            return self
        except (KeyError,ValueError,TypeError):raise SafeError('Invalid control intent') from None

    def binding(self):
        self.validated()
        return hashlib.sha256(canonical({'version':2,'principal':self.principal,'target':self.target,'action':self.action,'command':self.command,'payload':self.payload_json.decode()})).digest()

    def preview(self):
        self.validated()
        data=json.loads(self.payload_json)
        result={'action':self.action,'effect':SPECS[self.action].effect,'command':self.command,
                'dry_run':True,'executed':False,'execution_enabled':False,
                'required_scope':SPECS[self.action].scope,'estimated_gross_reservation_microdollars':1000,
                'requires_exact_owner_confirmation':True}
        result['parameters']={'destination':'[redacted]'} if self.action=='navigation_send' else redacted(self.action,data)
        return result


@dataclass(frozen=True)
class Capabilities:
    scopes:frozenset=frozenset()
    pairing_verified:bool=False
    signing_proxy_verified:bool=False
    protocol_required:bool|None=None
    parked:bool|None=None
    cable_connected:bool|None=None
    motorized_charge_port:bool|None=None
    observed_at:float=0
    unsupported_actions:frozenset=frozenset()

    def blockers(self,action,now):
        spec=SPECS.get(action)
        if spec is None:return ['unsupported-control']
        reasons=[]
        if spec.scope not in self.scopes:reasons.append('required-scope-not-granted')
        if self.pairing_verified is not True:reasons.append('virtual-key-pairing-not-verified')
        if self.signing_proxy_verified is not True:reasons.append('signed-proxy-not-verified')
        if self.protocol_required is None:reasons.append('vehicle-command-protocol-not-verified')
        # Only the catalog's three Park-required actions need fresh gear evidence.
        # Other actions remain subject to their own explicit prerequisites.
        if spec.requires_park:
            if not 0<=now-self.observed_at<=60:reasons.append('vehicle-state-stale')
            if self.parked is not True:reasons.append('parked-state-not-verified')
        if action in self.unsupported_actions:reasons.append('hardware-or-firmware-unsupported')
        if spec.needs_cable and self.cable_connected is not True:reasons.append('charging-cable-not-verified')
        if spec.motorized_port and self.motorized_charge_port is not True:reasons.append('motorized-charge-port-not-verified')
        return reasons

    @classmethod
    def from_verified_metadata(cls,scopes,fleet_status,vehicle_state,observed_at,*,pairing_verified=False,signing_proxy_verified=False):
        # Pure parser of trusted owner-side observations. It does not fetch them.
        # A positive total key count does not prove THIS application's key paired.
        if not isinstance(fleet_status,dict) or not isinstance(vehicle_state,dict):raise SafeError('Trusted capability metadata required')
        protocol=fleet_status.get('vehicle_command_protocol_required')
        if type(protocol)is not bool:protocol=None
        def flag(key):
            value=vehicle_state.get(key)
            return value if type(value)is bool else None
        if type(observed_at)not in (float,int) or not 0<observed_at<1e12:raise SafeError('Invalid capability observation time')
        return cls(frozenset(scopes),pairing_verified is True,signing_proxy_verified is True,protocol,
                   flag('parked'),flag('cable_connected'),flag('motorized_charge_port'),observed_at)


class StagedControlAdapter:
    """Only the disabled transport or an explicit in-process MockProxy is accepted.

    There is no production enable flag, environment variable or HTTP execute tool.
    An eventual reviewed live adapter must preserve exact approval, scopes, signed
    proxy TLS, vehicle capability checks and the same durable gross budget.
    """
    def __init__(self,ledger,budget=None,transport=None,clock=time.time):
        if transport is not None and not isinstance(transport,(MockProxy,DisabledNetwork)):
            raise SafeError('Live control transport not enabled')
        self.ledger=ledger;self.clock=clock
        self.adapter=CommandAdapter(ledger,transport,budget)

    def submit(self,intent,approval,access_token,capabilities):
        intent.validated()
        if isinstance(self.adapter.transport,DisabledNetwork):
            self.ledger.consume(approval,intent)
            raise SafeError('Live controls disabled; no transport or spending reservation')
        # Burn even an approval whose prerequisites have changed.
        blockers=capabilities.blockers(intent.action,self.clock())
        if blockers:
            self.ledger.consume(approval,intent)
            raise SafeError('Control prerequisites unavailable; approval consumed')
        return self.adapter.submit(intent,approval,access_token)


class OwnerControlWorkflow:
    """Trusted operator-only intent review; never instantiate on MCP authority."""
    def __init__(self,owner,target,ledger,clock=time.time):
        self.owner=owner;self.target=target;self.ledger=ledger;self.clock=clock;self.pending={}

    def prepare(self,action,args):
        now=self.clock()
        self.pending={k:v for k,v in self.pending.items() if 0<=now-v[1]<300}
        if len(self.pending)>=32:raise SafeError('Control preview capacity reached')
        intent=ControlIntent.build(self.owner,self.target,action,args)
        reference=secrets.token_hex(16)
        self.pending[reference]=(intent,now)
        return reference,intent.preview()

    def owner_review(self,reference):
        intent,issued=self.pending.get(reference,(None,0))
        if intent is None or not 0<=self.clock()-issued<300:raise SafeError('Control preview expired')
        # Only a separate trusted operator UI may receive precise destination.
        return {'action':intent.action,'effect':SPECS[intent.action].effect,'parameters':json.loads(intent.payload_json)}

    def confirm(self,reference,reviewed_binding,*,owner):
        # The owner identity must come from authenticated operator session, not
        # a tool argument. UI must display owner_review before this one-use POST.
        if owner!=self.owner:raise SafeError('Owner confirmation refused')
        self.owner_review(reference)
        intent,_=self.pending.pop(reference)
        if not isinstance(reviewed_binding,bytes) or not __import__('hmac').compare_digest(reviewed_binding,intent.binding()):
            raise SafeError('Exact owner-reviewed intent mismatch')
        return intent,self.ledger.approve(intent,ttl=60)
