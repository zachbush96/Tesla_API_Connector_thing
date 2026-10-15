"""Protected local live integration. Construction is inert; both gates default off.

Only the configured signer can claim an already consumed owner operation. Tokens
stay in this local callback. Every outbound command is durably reserved before
its attempt. The host remains responsible for explicit human chat authorization.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import re
import secrets
import time
import urllib.request

from .audit import strict_object
from .controls import ControlIntent, SPECS, canonical
from .service import SafeError, NoRedirect
from .storage import digest
from .execution_grants import OneActionGrants
from .signing_diagnostics import checked_diagnostic, checked_local_transport, FIELDS, LEGACY_FIELDS, KINDS

SDK_COMMIT = '49977a18fd68567501d59e16a6c9e4a8b9348544'
VIN = re.compile(r'[A-HJ-NPR-Z0-9]{17}')
OPERATION = re.compile(r'[a-f0-9]{32}')
SHA256 = re.compile(r'[a-f0-9]{64}')
FAILURE = 'Protected signing operation refused; no retry; private details withheld'


def strict_json(raw, limit=65536):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        raise SafeError(FAILURE)
    try:
        return json.loads(raw, object_pairs_hook=strict_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise SafeError(FAILURE) from None


def derive_bridge_token(signer_token):
    if not isinstance(signer_token, str) or not 32 <= len(signer_token) <= 4096 or not signer_token.isascii() or any(c.isspace() for c in signer_token):
        raise SafeError('Protected signer capability required')
    return hmac.new(signer_token.encode(), b'tesla-connector-signer-bridge-v1', hashlib.sha256).hexdigest()


def wire_intent(intent):
    intent.validated()
    return {'version':2, 'principal':intent.principal, 'target':intent.target,
            'action':intent.action, 'command':intent.command, 'payload':intent.payload_json.decode()}


def checked_intent(value, owner, target, mode):
    if not isinstance(value, dict) or value.get('principal') != owner or value.get('target') != target:
        raise SafeError(FAILURE)
    if mode in ('verify_pairing','verify_infotainment'):
        if set(value) != {'version', 'principal', 'target', 'action'} or type(value['version']) is not int or value['version'] != 1 or value['action'] != mode:
            raise SafeError(FAILURE)
    elif mode == 'execute':
        if set(value) != {'version', 'principal', 'target', 'action', 'command', 'payload'} or type(value['version']) is not int or value['version'] != 2 or not isinstance(value['payload'], str):
            raise SafeError(FAILURE)
        try:
            ControlIntent(owner, target, value['action'], value['command'], value['payload'].encode()).validated()
        except Exception:
            raise SafeError(FAILURE) from None
    else:
        raise SafeError(FAILURE)
    return canonical(value)


class FleetCapabilityReader:
    """Three fixed requests, no cache, wake, proxy, redirect, fallback or retry.

    Official Fleet status and vehicle metadata are uncharged. One combined data
    request reserves $0.002 against the existing lifetime ledger before attempt.
    Response timestamps (not local receipt time) establish fresh parked evidence.
    """
    def __init__(self, target, budget, *, region='na', opener=None, clock=time.time):
        if not isinstance(target, str) or not VIN.fullmatch(target) or region not in ('na', 'eu', 'cn'):
            raise SafeError('Trusted capability target required')
        self.target, self.budget, self.clock = target, budget, clock
        suffix = 'cn' if region == 'cn' else 'com'
        self.origin = f'https://fleet-api.prd.{region}.vn.cloud.tesla.{suffix}'
        self.opener = opener

    @staticmethod
    def approved_opener():
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def _request(self, path, bearer, *, body=None, reserve_data=None, authorize_attempt=None):
        if self.opener is None:
            raise SafeError('Capability transport disabled; no vehicle request')
        from .storage import check_request_deadline, remaining_request_seconds
        check_request_deadline()
        if authorize_attempt is not None:
            authorize_attempt()
        request = urllib.request.Request(self.origin + '/api/1/' + path, data=body,
            headers={'Authorization':'Bearer ' + bearer, 'Accept':'application/json', 'Content-Type':'application/json'},
            method='GET' if body is None else 'POST')
        if reserve_data is not None:
            check_request_deadline()
            reserve_data()
        try:
            check_request_deadline()
            remaining = remaining_request_seconds()
            limit = min(10.0,remaining) if remaining is not None else 10.0
            from .remote_controls import bounded_open_read
            status,raw = bounded_open_read(self.opener,request,max_body=1048576,
                seconds=limit,cancel_check=check_request_deadline)
            if status != 200:
                raise ValueError()
            check_request_deadline()
            value = strict_json(raw, 1048576)
            if not isinstance(value, dict) or value.get('error') or not (isinstance(value.get('response'), dict) or (path.endswith('/mobile_enabled') and type(value.get('response'))is bool)):
                raise ValueError()
            return {'enabled':value['response']} if path.endswith('/mobile_enabled') else value['response']
        except Exception as error:
            if hasattr(error, 'close'):
                error.close()
            raise SafeError('Trusted vehicle facts unavailable; no wake or retry') from None

    def _timestamp(self, state):
        stamp = state.get('timestamp') if isinstance(state, dict) else None
        if type(stamp) is not int or not 0 < stamp < 10**15 or not 0 <= self.clock() - stamp / 1000 <= 60:
            raise SafeError('Fresh vehicle capability timestamp required')
        return stamp

    def observe(self, authorization, action, *, reserve_data=None, authorize_attempt=None):
        if 'vehicle_device_data' not in authorization['scopes']:
            raise SafeError('Required capability permission unavailable')
        bearer = authorization['bearer']
        status = self._request('vehicles/fleet_status', bearer, body=canonical({'vins':[self.target]}),authorize_attempt=authorize_attempt)
        info = status.get('vehicle_info', {}).get(self.target) if isinstance(status.get('vehicle_info'), dict) else None
        if not isinstance(info, dict) or type(info.get('vehicle_command_protocol_required')) is not bool:
            raise SafeError('Vehicle command protocol metadata unavailable')
        paired_vins = status.get('key_paired_vins')
        if not isinstance(paired_vins, list) or any(not isinstance(v, str) or not VIN.fullmatch(v) for v in paired_vins):
            raise SafeError('Vehicle pairing status metadata unavailable')
        meta = self._request('vehicles/' + self.target, bearer,authorize_attempt=authorize_attempt)
        if meta.get('vin') != self.target:
            raise SafeError('Vehicle target metadata unavailable; no wake or retry')
        if action == 'verify_pairing':
            if meta.get('state') != 'online':
                raise SafeError('Vehicle awake state unavailable; no wake or retry')
            # The nonphysical VEHICLE_SECURITY handshake does not require Park.
            # Current online metadata and protocol status are enough; no data read.
            return {'protocol_known':True, 'parked':False, 'awake':meta.get('state')=='online', 'cable':False,
                    'motorized_port':False, 'observed_unix_ms':int(self.clock()*1000),
                    'drive_observed_unix_ms':0,
                    'application_key_listed':self.target in paired_vins}
        if not SPECS[action].requires_park:
            required=SPECS[action].required_facts
            facts={'protocol_known':True,'parked':False,'awake':meta.get('state')=='online',
                'cable':False,'motorized_port':False,'cable_absent':False,'climate_active':False,
                'user_present':False,'mobile_access':False,'observed_unix_ms':int(self.clock()*1000),
                'drive_observed_unix_ms':0,'application_key_listed':self.target in paired_vins}
            if not required:return facts
            # Exactly one charged, action-specific read; no polling or paid gear query.
            endpoint='charge_state' if action in ('charge_start','charge_port_close') else 'climate_state' if 'climate_active'in required else 'vehicle_state'
            data=self._request('vehicles/'+self.target+'/vehicle_data?endpoints='+endpoint,bearer,
                reserve_data=reserve_data or (lambda:self.budget.reserve('data')),authorize_attempt=authorize_attempt)
            if data.get('vin')!=self.target:raise SafeError('Trusted prerequisite target unavailable')
            state=data.get(endpoint);stamp=self._timestamp(state);facts['observed_unix_ms']=stamp
            if endpoint=='charge_state':
                cable=state.get('conn_charge_cable');charging=state.get('charging_state')
                facts['cable']=type(cable)is str and cable in ('SAE','IEC','GB','Type1','Type2') and charging in ('Charging','Stopped','Complete','Starting','NoPower')
                facts['cable_absent']=charging=='Disconnected' and cable in (None,'')
                if action=='charge_port_close':
                    with self.budget.store.transaction() as db:
                        facts['motorized_port']=db.execute('SELECT 1 FROM trusted_vehicle_hardware WHERE owner_hash=? AND target_hash=? AND key_sha256=? AND motorized_port=1',
                            (self.budget.owner,digest(self.target),self.signing_key_sha256)).fetchone()is not None
            elif endpoint=='climate_state':facts['climate_active']=state.get('is_climate_on')is True or state.get('climate_keeper_mode')in ('on','dog','camp')
            else:
                facts['user_present']=state.get('is_user_present')is True
                facts['mobile_access']=self._request('vehicles/'+self.target+'/mobile_enabled',bearer,authorize_attempt=authorize_attempt).get('enabled')is True
            if not all(facts[k]for k in required):raise SafeError('Documented action prerequisites unavailable; no command sent')
            return facts
        data = self._request('vehicles/' + self.target + '/vehicle_data?endpoints=drive_state', bearer,
                             reserve_data=reserve_data or (lambda:self.budget.reserve('data')),authorize_attempt=authorize_attempt)
        if data.get('vin') != self.target:
            raise SafeError('Vehicle capability target unavailable')
        drive = data.get('drive_state')
        observed = self._timestamp(drive)
        drive_observed = observed
        speed = drive.get('speed')
        stopped = speed is None or (type(speed) in (int, float) and math.isfinite(speed) and speed == 0)
        gear = drive.get('shift_state')
        # Unknown/null Fleet gear can be resolved by a fresh signed SDK query;
        # demonstrated motion, known non-Park or malformed facts cannot.
        if not stopped or gear not in (None, 'P'):
            raise SafeError('Contradictory vehicle movement evidence; no physical action')
        # A null shift_state/zero speed does not establish Park. Unknown fails closed.
        parked = drive.get('shift_state') == 'P' and stopped
        cable = False
        motorized = False
        return {'protocol_known':True, 'parked':bool(parked), 'awake':True, 'cable':bool(cable),
                'motorized_port':bool(motorized), 'observed_unix_ms':observed,
                'drive_observed_unix_ms':drive_observed,
                'application_key_listed':self.target in paired_vins}


class SignerBridge:
    """Durable exact one-use claims and atomic per-attempt budget reservations."""
    def __init__(self, owner, target, oauth, budget, capability_source, signing_key_sha256,
                 *, execution_enabled=False, pairing_diagnostic_enabled=False, infotainment_diagnostic_enabled=False):
        if not isinstance(owner, str) or not owner or not isinstance(target, str) or not VIN.fullmatch(target) or not isinstance(signing_key_sha256, str) or not SHA256.fullmatch(signing_key_sha256):
            raise SafeError('Trusted signer enrollment required')
        if any(type(gate) is not bool for gate in (execution_enabled,pairing_diagnostic_enabled,infotainment_diagnostic_enabled)):
            raise SafeError('Explicit local activation gates required')
        if budget.store is not oauth.store or budget.owner != oauth.owner or budget.owner != digest(owner):
            raise SafeError('Signer must share the existing owner lifetime ledger')
        self.owner, self.target, self.oauth, self.budget = owner, target, oauth, budget
        self.store, self.source, self.key = budget.store, capability_source, signing_key_sha256
        self.execution_enabled, self.pairing_diagnostic_enabled = execution_enabled, pairing_diagnostic_enabled
        self.infotainment_diagnostic_enabled = infotainment_diagnostic_enabled
        self.grants = OneActionGrants(owner, target, signing_key_sha256, budget)
        with self.store.transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS signer_operations (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL, binding BLOB NOT NULL,
                mode TEXT NOT NULL, action TEXT NOT NULL, key_sha256 TEXT NOT NULL, issued REAL NOT NULL, expires REAL NOT NULL,
                phase TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_kind TEXT,
                generation INTEGER, data_attempts INTEGER NOT NULL DEFAULT 0, state_observed INTEGER,
                PRIMARY KEY(owner_hash,operation_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS signer_pairing (
                owner_hash TEXT NOT NULL, target_hash TEXT NOT NULL, key_sha256 TEXT NOT NULL,
                verified_at REAL NOT NULL, PRIMARY KEY(owner_hash,target_hash,key_sha256))''')
            db.execute('''CREATE TABLE IF NOT EXISTS signer_operation_facts (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL,
                drive_observed INTEGER NOT NULL,
                PRIMARY KEY(owner_hash,operation_hash))''')

            db.execute('''CREATE TABLE IF NOT EXISTS signer_diagnostics (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 32),
                stage TEXT NOT NULL, kind TEXT NOT NULL, evidence TEXT NOT NULL,
                PRIMARY KEY(owner_hash,operation_hash,sequence),
                UNIQUE(owner_hash,operation_hash,stage,kind))''')
            db.execute('''CREATE TABLE IF NOT EXISTS signer_local_transport (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL,
                evidence TEXT NOT NULL, PRIMARY KEY(owner_hash,operation_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS signer_response_diagnostics (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL,
                evidence TEXT NOT NULL, PRIMARY KEY(owner_hash,operation_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS infotainment_diagnostic_once (
                owner_hash TEXT NOT NULL, target_hash TEXT NOT NULL, key_sha256 TEXT NOT NULL,
                operation_hash TEXT NOT NULL, reserved_microdollars INTEGER NOT NULL DEFAULT 0
                    CHECK(reserved_microdollars BETWEEN 0 AND 1000),
                PRIMARY KEY(owner_hash,target_hash), UNIQUE(owner_hash,operation_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS infotainment_diagnostic_allowances (
                owner_hash TEXT NOT NULL, target_hash TEXT NOT NULL, key_sha256 TEXT NOT NULL,
                operation_hash TEXT NOT NULL, approval_hash TEXT NOT NULL, binding BLOB NOT NULL,
                issued REAL NOT NULL, expires REAL NOT NULL,
                max_microdollars INTEGER NOT NULL CHECK(max_microdollars=1000),
                CHECK(expires>issued AND expires<=issued+120),
                PRIMARY KEY(owner_hash,operation_hash), UNIQUE(owner_hash,approval_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS infotainment_diagnostic_reservations (
                owner_hash TEXT NOT NULL, operation_hash TEXT NOT NULL,
                reserved_microdollars INTEGER NOT NULL CHECK(reserved_microdollars=1000),
                reserved_at REAL NOT NULL, PRIMARY KEY(owner_hash,operation_hash))''')
            for table in ('infotainment_diagnostic_allowances','infotainment_diagnostic_reservations'):
                for change in ('UPDATE','DELETE'):
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS preserve_{table}_{change.lower()}
                        BEFORE {change} ON {table} BEGIN
                        SELECT RAISE(ABORT,'Diagnostic authority and reservations must be retained'); END''')
                # SQLite REPLACE can delete a conflicting row without firing
                # DELETE triggers when recursive_triggers is off. Refuse each
                # duplicate identity before it can erase retained authority.
                approval = ' OR prior.approval_hash=NEW.approval_hash' if table == 'infotainment_diagnostic_allowances' else ''
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS preserve_{table}_insert
                    BEFORE INSERT ON {table} WHEN EXISTS (
                        SELECT 1 FROM {table} AS prior WHERE prior.owner_hash=NEW.owner_hash
                        AND (prior.operation_hash=NEW.operation_hash {approval}))
                    BEGIN SELECT RAISE(ABORT,'Diagnostic identity cannot be replaced'); END''')

    def _enabled(self, mode):
        if mode == 'execute': return self.execution_enabled
        if mode == 'verify_pairing': return self.pairing_diagnostic_enabled
        if mode == 'verify_infotainment':
            return self.infotainment_diagnostic_enabled and not self.execution_enabled and not self.pairing_diagnostic_enabled
        return False

    def _cap(self, db):
        cap = db.execute('SELECT gross_limit FROM total_budget_caps WHERE owner_hash=?', (self.budget.owner,)).fetchone()
        if not cap or not 0 < cap[0] <= 100000:
            raise SafeError('Existing owner lifetime allowance required')

    def authorize_additional_infotainment(self, operation_id, approval_id, *, expires_at_unix=None):
        """Trusted local fresh approval only; inert gates and no transport access.

        The original consumed diagnostic remains intact. This immutable authority
        is bound to one new operation and cannot authorize any physical action.
        Approval provenance is checked by the local operator, never an RPC input.
        An explicit approval expiry can only shorten the 120-second maximum.
        """
        if (not isinstance(operation_id,str) or not OPERATION.fullmatch(operation_id)
                or not isinstance(approval_id,str) or not 1<=len(approval_id)<=256
                or not approval_id.isascii() or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in approval_id)
                or self.execution_enabled or self.pairing_diagnostic_enabled or self.infotainment_diagnostic_enabled):
            raise SafeError('Fresh local diagnostic authority refused')
        intent={'version':1,'principal':self.owner,'target':self.target,'action':'verify_infotainment'}
        binding=hashlib.sha256(checked_intent(intent,self.owner,self.target,'verify_infotainment')).digest()
        operation=digest(operation_id)
        with self.store.transaction() as db:
            now=self.store.now(db)
            expires=now+120 if expires_at_unix is None else expires_at_unix
            if (type(expires) not in (int,float) or not now<expires<=now+120
                    or not math.isfinite(expires)):
                raise SafeError('Fresh local diagnostic expiry refused')
            self._cap(db)
            cap=db.execute('SELECT gross_limit FROM total_budget_caps WHERE owner_hash=?',(self.budget.owner,)).fetchone()
            spent=db.execute('SELECT COALESCE(SUM(spent),0) FROM usage WHERE owner_hash=?',(self.budget.owner,)).fetchone()[0]
            old=db.execute('''SELECT key_sha256,operation_hash,reserved_microdollars
                FROM infotainment_diagnostic_once WHERE owner_hash=? AND target_hash=?''',
                (self.budget.owner,digest(self.target))).fetchone()
            if (not old or not hmac.compare_digest(old[0],self.key) or old[2]!=1000
                    or type(cap[0])is not int or type(spent)is not int or spent<0 or spent+1000>cap[0]):
                raise SafeError('Retained consumed diagnostic and lifetime headroom required')
            previous=db.execute('''SELECT mode,action,phase,attempts,last_kind,data_attempts,key_sha256
                FROM signer_operations WHERE owner_hash=? AND operation_hash=?''',
                (self.budget.owner,old[1])).fetchone()
            proof=db.execute('SELECT 1 FROM signer_pairing WHERE owner_hash=? AND target_hash=? AND key_sha256=?',
                (self.budget.owner,digest(self.target),self.key)).fetchone()
            lifecycle=db.execute('SELECT status FROM refresh_state WHERE owner_hash=?',(self.budget.owner,)).fetchone()
            existing=db.execute('SELECT 1 FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,operation)).fetchone()
            if (previous!=('verify_infotainment','verify_infotainment','finished',1,'handshake',0,self.key)
                    or proof is None or lifecycle!=('ready',) or existing is not None):
                raise SafeError('Retained diagnostic enrollment and ready lifecycle required')
            db.execute('''INSERT INTO infotainment_diagnostic_allowances
                (owner_hash,target_hash,key_sha256,operation_hash,approval_hash,binding,issued,expires,max_microdollars)
                VALUES(?,?,?,?,?,?,?,?,1000)''',
                (self.budget.owner,digest(self.target),self.key,operation,digest(approval_id),binding,now,expires))
        return {'authorized':True,'gross_reservation_microdollars_max':1000,'signed_command_attempts_max':1}

    def _additional_infotainment(self, db, operation, binding, now):
        row=db.execute('''SELECT target_hash,key_sha256,binding,issued,expires,max_microdollars
            FROM infotainment_diagnostic_allowances WHERE owner_hash=? AND operation_hash=?''',
            (self.budget.owner,operation)).fetchone()
        if row is not None and (row[0]!=digest(self.target) or not hmac.compare_digest(row[1],self.key)
                or not hmac.compare_digest(row[2],binding) or not row[3]<=now<row[4] or row[5]!=1000):
            raise SafeError(FAILURE)
        return row

    def register(self, operation_id, intent, mode, *, require_additional_infotainment=False):
        if not isinstance(operation_id, str) or not OPERATION.fullmatch(operation_id) or not self._enabled(mode):
            raise SafeError('Live signing disabled; no vehicle request or reservation')
        if type(require_additional_infotainment)is not bool or (require_additional_infotainment and mode!='verify_infotainment'):
            raise SafeError(FAILURE)
        raw = checked_intent(intent, self.owner, self.target, mode)
        with self.store.transaction() as db:
            now = self.store.now(db)
            self._cap(db)
            if db.execute('SELECT COUNT(*) FROM signer_operations WHERE owner_hash=? AND expires>?', (self.budget.owner, now)).fetchone()[0] >= 128:
                raise SafeError(FAILURE)
            expires = now + 120
            if mode == 'execute':
                _, grant_expires = self.grants.consume(db, digest(operation_id), hashlib.sha256(raw).digest())
                expires = min(expires, grant_expires)
            if mode == 'verify_infotainment':
                if self.execution_enabled or self.pairing_diagnostic_enabled:
                    raise SafeError('Infotainment diagnostic requires physical and pairing gates off')
                if not require_additional_infotainment:
                    db.execute('INSERT INTO infotainment_diagnostic_once(owner_hash,target_hash,key_sha256,operation_hash) VALUES(?,?,?,?)',
                        (self.budget.owner,digest(self.target),self.key,digest(operation_id)))
                else:
                    additional=self._additional_infotainment(db,digest(operation_id),hashlib.sha256(raw).digest(),now)
                    if additional is None:raise SafeError('Fresh local diagnostic authority required')
                    expires=min(expires,additional[4])
            db.execute('INSERT INTO signer_operations(owner_hash,operation_hash,binding,mode,action,key_sha256,issued,expires,phase) VALUES(?,?,?,?,?,?,?,?,?)',
                (self.budget.owner, digest(operation_id), hashlib.sha256(raw).digest(), mode, intent['action'], self.key, now, expires, 'registered'))

    def _row(self, db, operation_id):
        if not isinstance(operation_id, str) or not OPERATION.fullmatch(operation_id):
            raise SafeError(FAILURE)
        row = db.execute('SELECT binding,mode,action,issued,expires,phase,attempts,last_kind,generation,key_sha256 FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                         (self.budget.owner, digest(operation_id))).fetchone()
        now = self.store.now(db)
        if row is None or not row[3] <= now < row[4] or not self._enabled(row[1]) or not hmac.compare_digest(row[9], self.key):
            raise SafeError(FAILURE)
        if row[1] == 'execute':
            self.grants.validate(db, digest(operation_id))
        return row

    def _bound(self, row, binding):
        if not isinstance(binding, str) or not SHA256.fullmatch(binding) or not hmac.compare_digest(row[0], bytes.fromhex(binding)):
            raise SafeError(FAILURE)

    def finish(self, operation_id, *, accepted=False):
        if not isinstance(operation_id, str) or not OPERATION.fullmatch(operation_id): return
        with self.store.transaction() as db:
            db.execute("UPDATE signer_operations SET phase='finished' WHERE owner_hash=? AND operation_hash=?", (self.budget.owner, digest(operation_id)))
            # Nonphysical diagnostics never call a physical-grant lifecycle method.
            row=db.execute('SELECT mode FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(operation_id))).fetchone()
            if row == ('execute',): self.grants.finish(db, digest(operation_id), accepted=accepted)

    def accounting(self, operation_id):
        with self.store.transaction() as db:
            row = db.execute('SELECT attempts,data_attempts,phase,last_kind FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner, digest(operation_id))).fetchone()
            if row is None: raise SafeError(FAILURE)
            grant = db.execute('SELECT state FROM one_action_grants WHERE owner_hash=? AND operation_hash=? AND target_hash=? AND key_sha256=?',
                (self.budget.owner, digest(operation_id), digest(self.target), self.key)).fetchone()
            return {'command_requests':row[0], 'data_requests':row[1], 'pairing_stored':row[2] == 'paired',
                    'phase':row[2], 'last_kind':row[3], 'grant_consumed':grant == ('consumed',)}

    def reserve_prerequisite(self, operation_id):
        with self.store.transaction() as db:
            row = self._row(db, operation_id)
            count = db.execute('SELECT data_attempts FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner, digest(operation_id))).fetchone()[0]
            if row[1] != 'execute' or row[5] != 'claiming' or count != 0: raise SafeError(FAILURE)
            self._current_authorization(db,row)
            self._cap(db)
            self.grants.reserve(db, digest(operation_id), 2000)
            self.budget._reserve_in_transaction(db, 'data')
            db.execute('UPDATE signer_operations SET data_attempts=1 WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner, digest(operation_id)))

    def _current_authorization(self,db,row):
        required = 'vehicle_cmds' if row[1] in ('verify_pairing','verify_infotainment') else SPECS[row[2]].scope
        lifecycle = db.execute('SELECT status,generation FROM refresh_state WHERE owner_hash=?', (self.budget.owner,)).fetchone()
        tokens = self.oauth.vault.load()
        if lifecycle != ('ready', row[8]) or tokens.expires_at <= self.store.clock() + 60 or not {required,'vehicle_device_data'} <= tokens.scopes:
            raise SafeError(FAILURE)

    def authorize_prerequisite(self,operation_id):
        from .storage import check_request_deadline
        check_request_deadline()
        with self.store.transaction() as db:
            row=self._row(db,operation_id)
            if row[5] != 'claiming':raise SafeError(FAILURE)
            self._current_authorization(db,row)

    def claim(self, value):
        from .storage import check_request_deadline
        check_request_deadline()
        if not isinstance(value, dict) or set(value) != {'operation_id','intent','mode','signing_key_sha256'} or value['signing_key_sha256'] != self.key:
            raise SafeError(FAILURE)
        raw = checked_intent(value['intent'], self.owner, self.target, value['mode'])
        operation = value['operation_id']
        with self.store.transaction() as db:
            row = self._row(db, operation)
            if row[5] != 'registered' or row[1] != value['mode'] or not hmac.compare_digest(row[0], hashlib.sha256(raw).digest()):
                raise SafeError(FAILURE)
            db.execute("UPDATE signer_operations SET phase='claiming' WHERE owner_hash=? AND operation_hash=?", (self.budget.owner, digest(operation)))
        try:
            required = 'vehicle_cmds' if row[1] in ('verify_pairing','verify_infotainment') else SPECS[row[2]].scope
            check_request_deadline()
            auth = self.oauth.authorization((required, 'vehicle_device_data'))
            check_request_deadline()
            # A stored proof for this exact current key is required before paid
            # execution preflight. Pairing approval/key counts do not substitute.
            with self.store.transaction() as db:
                current=self._row(db,operation)
                if current[5] != 'claiming':raise SafeError(FAILURE)
                db.execute('UPDATE signer_operations SET generation=? WHERE owner_hash=? AND operation_hash=?',
                    (auth['generation'],self.budget.owner,digest(operation)))
                enrollment = db.execute('SELECT 1 FROM signer_pairing WHERE owner_hash=? AND target_hash=? AND key_sha256=?',
                    (self.budget.owner, digest(self.target), self.key)).fetchone() is not None
            if row[1] == 'execute' and not enrollment: raise SafeError(FAILURE)
            if row[1] == 'verify_infotainment':
                if not enrollment: raise SafeError(FAILURE)
                # The matched-key proof is retained, not rewritten. This separate
                # diagnostic never queries metadata/data, wakes, or refreshes OAuth.
                observed = {'protocol_known':True,'parked':False,'awake':False,'cable':False,
                    'motorized_port':False,'application_key_listed':True,
                    'observed_unix_ms':int(self.store.clock()*1000),'drive_observed_unix_ms':0}
            else:
                observed = self.source.observe(auth, row[2], reserve_data=lambda:self.reserve_prerequisite(operation),
                    authorize_attempt=lambda:self.authorize_prerequisite(operation))
            flags = ('protocol_known','parked','awake','cable','motorized_port','application_key_listed','cable_absent','climate_active','user_present','mobile_access')
            observed={**{k:False for k in ('cable_absent','climate_active','user_present','mobile_access')},**observed}
            if not isinstance(observed, dict) or set(observed) != set(flags) | {'observed_unix_ms','drive_observed_unix_ms'} or any(type(observed[k]) is not bool for k in flags):
                raise SafeError(FAILURE)
            stamp = observed['observed_unix_ms']
            if type(stamp) is not int or not 0 <= self.store.clock() - stamp / 1000 <= 60:
                raise SafeError(FAILURE)
            drive_stamp = observed['drive_observed_unix_ms']
            if row[1] == 'execute' and SPECS[row[2]].requires_park:
                if type(drive_stamp) is not int or drive_stamp < stamp or not 0 <= self.store.clock() - drive_stamp / 1000 <= 60:
                    raise SafeError(FAILURE)
            elif type(drive_stamp) is not int or drive_stamp != 0:
                raise SafeError(FAILURE)
            if not observed['protocol_known'] or (row[1] == 'verify_pairing' and not observed['awake']):
                raise SafeError(FAILURE)
            with self.store.transaction() as db:
                current = self._row(db, operation)
                if current[5] != 'claiming': raise SafeError(FAILURE)
                self._current_authorization(db,current)
                paired = observed['application_key_listed'] and db.execute('SELECT 1 FROM signer_pairing WHERE owner_hash=? AND target_hash=? AND key_sha256=?',
                    (self.budget.owner, digest(self.target), self.key)).fetchone() is not None
                if row[1] == 'execute' and not paired: raise SafeError(FAILURE)
                if row[1] == 'execute' and SPECS[row[2]].requires_park:
                    db.execute('INSERT INTO signer_operation_facts VALUES(?,?,?)', (self.budget.owner, digest(operation), drive_stamp))
                db.execute("UPDATE signer_operations SET phase='claimed',generation=? WHERE owner_hash=? AND operation_hash=?", (auth['generation'], self.budget.owner, digest(operation)))
            facts = {k:observed[k] for k in flags if k != 'application_key_listed'}
            facts.update({'scopes':sorted(auth['scopes']), 'paired':bool(paired),
                          'signing_ready':bool(paired and observed['protocol_known']), 'observed_unix_ms':stamp,
                          'drive_observed_unix_ms':drive_stamp})
            return {'bearer':auth['bearer'], 'facts':facts}
        except Exception:
            self.finish(operation)
            raise SafeError(FAILURE) from None

    def reserve(self, value):
        if not isinstance(value, dict) or set(value) != {'operation_id','binding_sha256','category','kind','attempt'} or value['category'] != 'commands' or type(value['attempt']) is not int:
            raise SafeError(FAILURE)
        # Expiry/lifecycle/scope checked without forcing refresh. A rotation or
        # replaced consent invalidates an in-flight claim's remaining attempts.
        with self.store.transaction() as db:
            row = self._row(db, value['operation_id'])
            self._bound(row, value['binding_sha256'])
            if row[5] not in ('claimed','state_verified') or value['attempt'] != row[6] + 1: raise SafeError(FAILURE)
            self._current_authorization(db,row)
            count, kind = row[6], value['kind']
            if row[1] in ('verify_pairing','verify_infotainment'): allowed = count == 0 and kind == 'handshake'
            elif not SPECS[row[2]].requires_park:
                if row[2] == 'navigation_send':
                    allowed = row[5] == 'claimed' and count == 0 and kind == 'navigation'
                else:
                    allowed = row[5] == 'claimed' and ((count == 0 and kind == 'handshake') or
                              (count == 1 and row[7] == 'handshake' and kind == 'command'))
            elif count == 0: allowed = row[5] == 'claimed' and kind == 'state_handshake'
            elif count == 1: allowed = row[5] == 'claimed' and row[7] == 'state_handshake' and kind == 'state_query'
            else:
                stamp = db.execute('SELECT state_observed FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                    (self.budget.owner, digest(value['operation_id']))).fetchone()[0]
                fresh = type(stamp) is int and 0 <= self.store.clock() - stamp / 1000 <= 60
                allowed = row[5] == 'state_verified' and fresh and count == 2 and kind == 'command'
            if not allowed: raise SafeError(FAILURE)
            self._cap(db)
            if row[1] == 'execute':
                self.grants.reserve(db, digest(value['operation_id']), 1000)
            if row[1] == 'verify_infotainment':
                now=self.store.now(db)
                additional=self._additional_infotainment(db,digest(value['operation_id']),row[0],now)
                if additional is None:
                    result=db.execute('''UPDATE infotainment_diagnostic_once SET reserved_microdollars=1000
                        WHERE owner_hash=? AND target_hash=? AND key_sha256=? AND operation_hash=?
                          AND reserved_microdollars=0''',
                        (self.budget.owner,digest(self.target),self.key,digest(value['operation_id'])))
                    if result.rowcount != 1: raise SafeError(FAILURE)
                else:
                    db.execute('''INSERT INTO infotainment_diagnostic_reservations
                        (owner_hash,operation_hash,reserved_microdollars,reserved_at) VALUES(?,?,1000,?)''',
                        (self.budget.owner,digest(value['operation_id']),now))
            self.budget._reserve_in_transaction(db, 'commands')
            db.execute('UPDATE signer_operations SET attempts=?,last_kind=? WHERE owner_hash=? AND operation_hash=?',
                       (count + 1, kind, self.budget.owner, digest(value['operation_id'])))
        return {'reserved':True}

    def state(self, value):
        if not isinstance(value, dict) or set(value) != {'operation_id','binding_sha256','signing_key_sha256','parked','awake','observed_unix_ms','sdk_commit'} or value['parked'] is not True or value['awake'] is not True or value['sdk_commit'] != SDK_COMMIT or value['signing_key_sha256'] != self.key:
            raise SafeError(FAILURE)
        stamp = value['observed_unix_ms']
        if type(stamp) is not int or not 0 <= self.store.clock() - stamp / 1000 <= 60: raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row = self._row(db, value['operation_id'])
            self._bound(row, value['binding_sha256'])
            if row[1] != 'execute' or row[5] != 'claimed' or row[6] != 2 or row[7] != 'state_query': raise SafeError(FAILURE)
            drive = db.execute('SELECT drive_observed FROM signer_operation_facts WHERE owner_hash=? AND operation_hash=?',
                               (self.budget.owner, digest(value['operation_id']))).fetchone()
            if drive is None or stamp < drive[0]:
                raise SafeError(FAILURE)
            db.execute("UPDATE signer_operations SET phase='state_verified',state_observed=? WHERE owner_hash=? AND operation_hash=?",
                (stamp, self.budget.owner, digest(value['operation_id'])))
        return {'stored':True}

    def pairing(self, value):
        if not isinstance(value, dict) or set(value) != {'operation_id','binding_sha256','signing_key_sha256','pairing_verified','sdk_commit'} or value['pairing_verified'] is not True or value['sdk_commit'] != SDK_COMMIT or value['signing_key_sha256'] != self.key:
            raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row = self._row(db, value['operation_id'])
            self._bound(row, value['binding_sha256'])
            if row[1] != 'verify_pairing' or row[5] != 'claimed' or row[6] != 1 or row[7] != 'handshake': raise SafeError(FAILURE)
            now = self.store.now(db)
            db.execute('INSERT INTO signer_pairing VALUES(?,?,?,?) ON CONFLICT(owner_hash,target_hash,key_sha256) DO UPDATE SET verified_at=excluded.verified_at',
                       (self.budget.owner, digest(self.target), self.key, now))
            db.execute("UPDATE signer_operations SET phase='paired' WHERE owner_hash=? AND operation_hash=?", (self.budget.owner, digest(value['operation_id'])))
        return {'stored':True}

    def diagnostic(self, value):
        envelope={'operation_id','binding_sha256','sequence'}
        if type(value) is not dict or set(value) not in (envelope | FIELDS,envelope | LEGACY_FIELDS):
            raise SafeError(FAILURE)
        evidence=checked_diagnostic({k:v for k,v in value.items() if k not in envelope})
        sequence=value['sequence']
        if type(sequence) is not int or not 1 <= sequence <= 32: raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row=self._row(db,value['operation_id'])
            self._bound(row,value['binding_sha256'])
            kind=evidence['kind']
            allowed={'operation','handshake'} if row[1] in ('verify_pairing','verify_infotainment') else {'operation','handshake','command','state_handshake','state_query','navigation'}
            if kind not in allowed: raise SafeError(FAILURE)
            # Any network checkpoint requires a committed durable reservation;
            # a speculative or fabricated acknowledgement is rejected.
            if evidence['reservation_acknowledged'] and (row[6] < 1 or (kind != 'operation' and kind != row[7])):
                raise SafeError(FAILURE)
            count=db.execute('SELECT COUNT(*) FROM signer_diagnostics WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(value['operation_id']))).fetchone()[0]
            if sequence != count + 1 or count >= 32: raise SafeError(FAILURE)
            db.execute('INSERT INTO signer_diagnostics VALUES(?,?,?,?,?,?)',
                (self.budget.owner,digest(value['operation_id']),sequence,evidence['stage'],kind,canonical(evidence).decode()))
        return {'stored':True}

    def diagnostics(self, operation_id):
        if not isinstance(operation_id,str) or not OPERATION.fullmatch(operation_id): raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row=db.execute('SELECT evidence FROM signer_response_diagnostics WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(operation_id))).fetchone()
            if row is None:
                row=db.execute('SELECT evidence FROM signer_diagnostics WHERE owner_hash=? AND operation_hash=? ORDER BY sequence DESC LIMIT 1',
                    (self.budget.owner,digest(operation_id))).fetchone()
        return checked_diagnostic(strict_json(row[0].encode(),4096)) if row else None

    def record_response_diagnostic(self, operation_id, value):
        """Retain a bounded TLS signer receipt even if its callback was lost.

        This is a local client API, never an HTTP/MCP arm/reset/diagnostic route.
        Evidence is immutable per operation and cannot invent a reservation.
        """
        evidence=checked_diagnostic(value)
        if not isinstance(operation_id,str) or not OPERATION.fullmatch(operation_id):raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row=db.execute('SELECT attempts,last_kind,key_sha256,mode FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(operation_id))).fetchone()
            if row is None or row[2]!=self.key:raise SafeError(FAILURE)
            allowed={'operation','handshake'} if row[3] in ('verify_pairing','verify_infotainment') else KINDS
            if evidence['kind'] not in allowed:raise SafeError(FAILURE)
            if evidence['reservation_acknowledged'] and (row[0]<1 or (evidence['kind']!='operation' and evidence['kind']!=row[1])):
                raise SafeError(FAILURE)
            raw=canonical(evidence).decode()
            prior=db.execute('SELECT evidence FROM signer_response_diagnostics WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(operation_id))).fetchone()
            if prior is not None:
                if checked_diagnostic(strict_json(prior[0].encode(),4096))!=evidence:raise SafeError(FAILURE)
                return
            db.execute('INSERT INTO signer_response_diagnostics VALUES(?,?,?)',
                (self.budget.owner,digest(operation_id),raw))

    def record_local_transport(self, operation_id, value):
        evidence=checked_local_transport(value)
        if not isinstance(operation_id,str) or not OPERATION.fullmatch(operation_id): raise SafeError(FAILURE)
        with self.store.transaction() as db:
            row=db.execute('SELECT 1 FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
                (self.budget.owner,digest(operation_id))).fetchone()
            if row is None: raise SafeError(FAILURE)
            db.execute('INSERT INTO signer_local_transport VALUES(?,?,?)',
                (self.budget.owner,digest(operation_id),canonical(evidence).decode()))

    def handle(self, path, raw):
        try:
            value = strict_json(raw, 16384)
            action = {'/internal/signer/claim':self.claim, '/internal/signer/reserve':self.reserve,
                      '/internal/signer/pairing':self.pairing, '/internal/signer/state':self.state,
                      '/internal/signer/diagnostic':self.diagnostic}.get(path)
            if action is None: return 404, {'error':FAILURE}
            return 200, action(value)
        except Exception:
            return 403, {'error':FAILURE}


@dataclass(repr=False)
class LiveControlRuntime:
    bridge: object = field(repr=False)
    bridge_token: str = field(repr=False)
    executor: object = field(repr=False)
    verifier: object = field(repr=False)
    operations: object = field(repr=False)
    infotainment_verifier: object = field(repr=False)


def compose_live_controls(runtime, owner, target, *, certificate_path, signer_token,
                          signing_key_sha256, bridge_token=None, execution_enabled=False,
                          pairing_diagnostic_enabled=False, infotainment_diagnostic_enabled=False, capability_opener=None, clock=time.time):
    """No network, credential rotation or budget reset. Pass approved transports explicitly."""
    from .remote_controls import SignerLiveExecutor, SignerPairingVerifier, SignerInfotainmentVerifier, RemoteOperations
    derived = derive_bridge_token(signer_token)
    if bridge_token is not None and (not isinstance(bridge_token, str) or not hmac.compare_digest(derived, bridge_token)):
        raise SafeError('Distinct internal signer capability required')
    region = runtime.service.config.region
    source = FleetCapabilityReader(target, runtime.budget, region=region, opener=capability_opener, clock=clock)
    source.signing_key_sha256=signing_key_sha256
    bridge = SignerBridge(owner, target, runtime.oauth, runtime.budget, source, signing_key_sha256,
                         execution_enabled=execution_enabled, pairing_diagnostic_enabled=pairing_diagnostic_enabled,
                         infotainment_diagnostic_enabled=infotainment_diagnostic_enabled)
    executor = SignerLiveExecutor(certificate_path, signer_token, bridge, enabled=execution_enabled)
    verifier = SignerPairingVerifier(certificate_path, signer_token, bridge, enabled=pairing_diagnostic_enabled)
    operations = RemoteOperations(owner, target, executor=executor)
    infotainment=SignerInfotainmentVerifier(certificate_path,signer_token,bridge,enabled=infotainment_diagnostic_enabled)
    return LiveControlRuntime(bridge, derived, executor, verifier, operations, infotainment)
