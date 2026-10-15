"""Trusted local, durable authorization for one exact bounded physical action.

Arming/revocation are operator-only APIs, never HTTP or MCP tools. The local
owner must review the exact intent, maximum gross reservation and expiry. These
APIs neither enable a service nor make a vehicle request. An uncertain consumed
grant blocks new grants until separately authorized evidence reconciliation;
expiry and restart cannot resolve it or recreate the old authorization.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets

from .controls import ControlIntent, SPECS, canonical, payload
from .service import SafeError
from .storage import digest
from .signing_diagnostics import (checked_diagnostic,
                                  checked_local_transport)


_HASH = re.compile(r'[a-f0-9]{64}')
_GRANT_ID = re.compile(r'[a-f0-9]{32}')
_VIN = re.compile(r'[A-HJ-NPR-Z0-9]{17}')
_SECURITY_ACTIONS = frozenset(('lock', 'unlock', 'front_trunk', 'rear_trunk'))
_FAILURE = 'One-action execution grant unavailable; no request or retry'
_RECONCILIATION_FAILURE = 'Local grant reconciliation refused; original grant remains denied'
_DECISIONS = frozenset(('zero_physical_transmission', 'acknowledge_unknown'))


@dataclass(frozen=True)
class LegacyReservationAudit:
    """Private local attestation of a reviewed historical build and audit.

    Before constructing this, the operator must verify the four actual artifacts
    using bounded, owner-regular, nofollow reads; hashes alone are not provenance.
    The historical audit must establish that this deployed build used the same
    guarded physical reservation-before-wire path for this exact operation.
    This attestation is insufficient without the independently checked positive
    atomic grant/operation/usage evidence. Never infer it from a current build,
    missing diagnostics, a timeout, an operator recollection or vehicle state.
    """
    historical_artifact_sha256: str = field(repr=False)
    guard_source_sha256: str = field(repr=False)
    atomic_bridge_source_sha256: str = field(repr=False)
    historical_audit_sha256: str = field(repr=False)
    provenance_reviewed: bool
    profile: str = 'set_temperature_handshake_only_v1'


@dataclass(frozen=True)
class GrantReconciliationPlan:
    """Private immutable review handle. Do not log its identifiers or snapshot."""
    owner_hash: str = field(repr=False)
    target_hash: str = field(repr=False)
    key_sha256: str = field(repr=False)
    operation_hash: str = field(repr=False)
    grant_hash: str = field(repr=False)
    evidence_sha256: str = field(repr=False)
    snapshot_json: str = field(repr=False)
    action: str
    zero_physical_transmission_proven: bool
    legacy_audit: LegacyReservationAudit | None = field(default=None, repr=False)

    def summary(self):
        return {'action': self.action,
                'zero_physical_transmission_proven': self.zero_physical_transmission_proven,
                'original_grant_denied': True, 'creates_execution_authority': False,
                'unknown_acknowledgment_keeps_blocking': True,
                'evidence_profile': ('legacy_atomic_reservation_audit' if self.legacy_audit
                                     else 'complete_durable_handshake_trace')}


class OneActionGrants:
    """Journal shared with the existing private lifetime budget transaction.

Only an armed matching grant can be consumed. The caller commits consumption
and operation registration in the same transaction before invoking preflight.
Per-attempt grant and lifetime debits must likewise share one transaction.
"""
    def __init__(self, owner, target, signing_key_sha256, budget):
        if (not isinstance(owner, str) or not 0 < len(owner) <= 256
                or not isinstance(target, str) or not _VIN.fullmatch(target)
                or not isinstance(signing_key_sha256, str)
                or not _HASH.fullmatch(signing_key_sha256)
                or getattr(budget, 'owner', None) != digest(owner)):
            raise SafeError(_FAILURE)
        self.owner, self.target, self.key = owner, target, signing_key_sha256
        self.budget, self.store = budget, budget.store
        self.owner_hash, self.target_hash = digest(owner), digest(target)
        with self.store.transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS one_action_grants (
                owner_hash TEXT NOT NULL, grant_hash TEXT NOT NULL,
                target_hash TEXT NOT NULL, key_sha256 TEXT NOT NULL,
                binding BLOB NOT NULL, action TEXT NOT NULL,
                issued REAL NOT NULL, expires REAL NOT NULL,
                state TEXT NOT NULL CHECK(state IN
                    ('armed','consumed','accepted','uncertain','revoked')),
                operation_hash TEXT,
                max_gross_microdollars INTEGER NOT NULL CHECK(max_gross_microdollars > 0),
                navigation_timestamp_ms TEXT,
                reserved_microdollars INTEGER NOT NULL DEFAULT 0
                    CHECK(reserved_microdollars >= 0
                          AND reserved_microdollars <= max_gross_microdollars),
                PRIMARY KEY(owner_hash, grant_hash))''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(one_action_grants)')}
            if 'navigation_timestamp_ms' not in columns:
                # Existing grants retain their binding; a legacy navigation row
                # without a pinned timestamp cannot prepare and fails closed.
                db.execute('ALTER TABLE one_action_grants ADD COLUMN navigation_timestamp_ms TEXT')
            db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS one_action_grant_operation
                ON one_action_grants(owner_hash, operation_hash)
                WHERE operation_hash IS NOT NULL''')
            db.execute('''CREATE TABLE IF NOT EXISTS grant_reconciliation_authorizations (
                owner_hash TEXT NOT NULL, authorization_hash TEXT NOT NULL,
                approval_hash TEXT NOT NULL, target_hash TEXT NOT NULL,
                key_sha256 TEXT NOT NULL, operation_hash TEXT NOT NULL,
                grant_hash TEXT NOT NULL, evidence_sha256 TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN
                    ('zero_physical_transmission','acknowledge_unknown')),
                issued REAL NOT NULL, expires REAL NOT NULL,
                CHECK(expires > issued AND expires <= issued + 120),
                PRIMARY KEY(owner_hash,authorization_hash), UNIQUE(owner_hash,approval_hash))''')
            db.execute('''CREATE TABLE IF NOT EXISTS grant_reconciliations (
                owner_hash TEXT NOT NULL, authorization_hash TEXT NOT NULL,
                approval_hash TEXT NOT NULL, target_hash TEXT NOT NULL,
                key_sha256 TEXT NOT NULL, operation_hash TEXT NOT NULL,
                grant_hash TEXT NOT NULL, evidence_sha256 TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN
                    ('zero_physical_transmission','acknowledge_unknown')),
                recorded REAL NOT NULL, snapshot_json TEXT NOT NULL,
                PRIMARY KEY(owner_hash,authorization_hash), UNIQUE(owner_hash,approval_hash),
                UNIQUE(owner_hash,grant_hash))''')
            db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS grant_reconciliation_zero_once
                ON grant_reconciliations(owner_hash,grant_hash)
                WHERE decision='zero_physical_transmission' ''')
            for table in ('grant_reconciliation_authorizations', 'grant_reconciliations'):
                for verb in ('UPDATE', 'DELETE'):
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS preserve_{table}_{verb.lower()}
                        BEFORE {verb} ON {table} BEGIN
                        SELECT RAISE(ABORT,'Reconciliation evidence is append only'); END''')
                # REPLACE can otherwise bypass DELETE triggers with SQLite's
                # default recursive_triggers=OFF. Reject duplicate identities
                # before any replacement can erase the immutable record.
                extra = ' OR prior.grant_hash=NEW.grant_hash' if table == 'grant_reconciliations' else ''
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS preserve_{table}_insert
                    BEFORE INSERT ON {table} WHEN EXISTS (
                        SELECT 1 FROM {table} AS prior WHERE prior.owner_hash=NEW.owner_hash
                        AND (prior.authorization_hash=NEW.authorization_hash
                             OR prior.approval_hash=NEW.approval_hash {extra}))
                    BEGIN SELECT RAISE(ABORT,'Reconciliation identity cannot be replaced'); END''')

    def _cap(self, db, *, required=0):
        cap = db.execute('SELECT gross_limit FROM total_budget_caps WHERE owner_hash=?',
                         (self.owner_hash,)).fetchone()
        reserved = db.execute('SELECT COALESCE(SUM(spent),0) FROM usage WHERE owner_hash=?',
                              (self.owner_hash,)).fetchone()[0]
        if (cap is None or type(cap[0]) is not int or not 0 < cap[0] <= 100000
                or type(reserved) is not int or reserved < 0
                or reserved + required > cap[0]):
            raise SafeError(_FAILURE)

    @staticmethod
    def _operation_hash(operation_hash):
        if not isinstance(operation_hash, str) or not _HASH.fullmatch(operation_hash):
            raise SafeError(_FAILURE)

    def arm(self, intent, maximum_gross_microdollars, ttl_seconds=300):
        """Owner-local reviewed action only; does not enable either live gate."""
        if (type(intent) is not ControlIntent or intent.principal != self.owner
                or intent.target != self.target):
            raise SafeError(_FAILURE)
        binding = intent.binding()
        navigation_timestamp = None
        if intent.action == 'navigation_send':
            navigation_timestamp = json.loads(intent.payload_json)['timestamp_ms']
            if not isinstance(navigation_timestamp, str) or not re.fullmatch(r'[0-9]{13}', navigation_timestamp):
                raise SafeError(_FAILURE)
        ceiling = 6000 if intent.action in _SECURITY_ACTIONS else 5000
        if (type(maximum_gross_microdollars) is not int
                or not 0 < maximum_gross_microdollars <= ceiling
                or type(ttl_seconds) not in (int, float)
                or not 0 < ttl_seconds <= 300):
            raise SafeError(_FAILURE)
        grant_id = secrets.token_hex(16)
        with self.store.transaction() as db:
            now = self.store.now(db)
            self._cap(db, required=maximum_gross_microdollars)
            # A changed signing key cannot bypass an unresolved action. Expired
            # unconsumed grants may be replaced; consumed ones are retained.
            unresolved = db.execute('''SELECT 1 FROM one_action_grants AS g
                WHERE g.owner_hash=? AND g.target_hash=? AND
                (g.state='consumed' OR (g.state='armed' AND g.expires>?) OR
                 (g.state='uncertain' AND NOT EXISTS (
                    SELECT 1 FROM grant_reconciliations AS r
                    WHERE r.owner_hash=g.owner_hash AND r.grant_hash=g.grant_hash
                      AND r.operation_hash=g.operation_hash AND r.target_hash=g.target_hash
                      AND r.key_sha256=g.key_sha256
                      AND r.decision='zero_physical_transmission')))
                LIMIT 1''', (self.owner_hash, self.target_hash, now)).fetchone()
            if unresolved is not None:
                raise SafeError(_FAILURE)
            db.execute("""UPDATE one_action_grants SET state='revoked'
                WHERE owner_hash=? AND target_hash=? AND state='armed' AND expires<=?""",
                (self.owner_hash, self.target_hash, now))
            db.execute('''INSERT INTO one_action_grants
                (owner_hash,grant_hash,target_hash,key_sha256,binding,action,
                 issued,expires,state,max_gross_microdollars,navigation_timestamp_ms)
                VALUES(?,?,?,?,?,?,?,?,'armed',?,?)''',
                (self.owner_hash, digest(grant_id), self.target_hash, self.key,
                 binding, intent.action, now, now + ttl_seconds,
                 maximum_gross_microdollars, navigation_timestamp))
        return grant_id

    def prepare_intent(self, action, parameters):
        """Reconstruct navigation with its reviewed timestamp; never reissue it.

        The only navigation metadata retained is a timestamp and exact intent
        hash. Destination text stays in the caller's proposal and is checked
        against that hash. Preparation neither consumes nor reserves a grant.
        """
        if action != 'navigation_send':
            return ControlIntent.build(self.owner, self.target, action, parameters)
        with self.store.transaction() as db:
            now = self.store.now(db)
            rows = db.execute('''SELECT binding,issued,expires,navigation_timestamp_ms
                FROM one_action_grants WHERE owner_hash=? AND target_hash=?
                  AND key_sha256=? AND action='navigation_send' AND state='armed' ''',
                (self.owner_hash, self.target_hash, self.key)).fetchall()
            if len(rows) != 1:
                raise SafeError(_FAILURE)
            binding, issued, expires, timestamp = rows[0]
            if (not issued <= now < expires or not isinstance(timestamp, str)
                    or not re.fullmatch(r'[0-9]{13}', timestamp)):
                raise SafeError(_FAILURE)
            intent = ControlIntent(self.owner, self.target, action, SPECS[action].endpoint,
                canonical(payload(action, parameters, timestamp)))
            if not hmac.compare_digest(intent.binding(), binding):
                raise SafeError(_FAILURE)
            return intent

    def revoke(self, grant_id):
        """Revoke only an unused grant; cannot clear an uncertain outcome."""
        if not isinstance(grant_id, str) or not _GRANT_ID.fullmatch(grant_id):
            raise SafeError(_FAILURE)
        with self.store.transaction() as db:
            self.store.now(db)
            result = db.execute("""UPDATE one_action_grants SET state='revoked'
                WHERE owner_hash=? AND target_hash=? AND key_sha256=?
                  AND grant_hash=? AND state='armed'""",
                (self.owner_hash, self.target_hash, self.key, digest(grant_id)))
            if result.rowcount != 1:
                raise SafeError(_FAILURE)

    def consume(self, db, operation_hash, intent_binding):
        """Atomically bind one operation; caller owns the existing transaction."""
        self._operation_hash(operation_hash)
        if not isinstance(intent_binding, bytes) or len(intent_binding) != 32:
            raise SafeError(_FAILURE)
        now = self.store.now(db)
        rows = db.execute('''SELECT grant_hash,binding,issued,expires,max_gross_microdollars
            FROM one_action_grants WHERE owner_hash=? AND target_hash=?
              AND key_sha256=? AND state='armed' ''',
            (self.owner_hash, self.target_hash, self.key)).fetchall()
        if len(rows) != 1:
            raise SafeError(_FAILURE)
        grant_hash, binding, issued, expires, maximum = rows[0]
        if not issued <= now < expires or not hmac.compare_digest(binding, intent_binding):
            raise SafeError(_FAILURE)
        self._cap(db, required=maximum)
        result = db.execute("""UPDATE one_action_grants
            SET state='consumed',operation_hash=?
            WHERE owner_hash=? AND grant_hash=? AND state='armed'""",
            (operation_hash, self.owner_hash, grant_hash))
        if result.rowcount != 1:
            raise SafeError(_FAILURE)
        return grant_hash, expires

    def _consumed(self, db, operation_hash):
        self._operation_hash(operation_hash)
        now = self.store.now(db)
        row = db.execute('''SELECT issued,expires,state,target_hash,key_sha256,
            max_gross_microdollars,reserved_microdollars FROM one_action_grants
            WHERE owner_hash=? AND operation_hash=?''',
            (self.owner_hash, operation_hash)).fetchone()
        if (row is None or row[2] != 'consumed' or not row[0] <= now < row[1]
                or not hmac.compare_digest(row[3], self.target_hash)
                or not hmac.compare_digest(row[4], self.key)):
            raise SafeError(_FAILURE)
        self._cap(db)
        return row

    def validate(self, db, operation_hash):
        self._consumed(db, operation_hash)

    def reserve(self, db, operation_hash, amount):
        """Debit before attempt, in the same transaction as the lifetime debit."""
        if type(amount) is not int or amount not in (1000, 2000):
            raise SafeError(_FAILURE)
        row = self._consumed(db, operation_hash)
        if row[6] + amount > row[5]:
            raise SafeError(_FAILURE)
        self._cap(db, required=amount)
        result = db.execute('''UPDATE one_action_grants
            SET reserved_microdollars=reserved_microdollars+?
            WHERE owner_hash=? AND operation_hash=? AND state='consumed'
              AND reserved_microdollars+?<=max_gross_microdollars''',
            (amount, self.owner_hash, operation_hash, amount))
        if result.rowcount != 1:
            raise SafeError(_FAILURE)

    def finish(self, db, operation_hash, accepted=False):
        """Only a validated submission receipt establishes a known outcome.

        No receipt, malformed response, crash, or refusal is uncertain for this
        journal. A later repeated finish cannot turn uncertainty into acceptance.
        Expiry does not prevent recording the outcome, and never re-arms a grant.
        """
        self._operation_hash(operation_hash)
        if type(accepted) is not bool:
            raise SafeError(_FAILURE)
        self.store.now(db)
        db.execute("""UPDATE one_action_grants SET state=?
            WHERE owner_hash=? AND target_hash=? AND key_sha256=?
              AND operation_hash=? AND state='consumed'""",
            ('accepted' if accepted else 'uncertain', self.owner_hash,
             self.target_hash, self.key, operation_hash))

    @staticmethod
    def _json_evidence(raw, checker):
        # Bounded enum-only evidence, never exception messages or raw responses.
        if type(raw) is not str or len(raw.encode()) > 4096:
            raise SafeError(_RECONCILIATION_FAILURE)
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise SafeError(_RECONCILIATION_FAILURE)
                value[key] = item
            return value
        try:
            return checker(json.loads(raw, object_pairs_hook=pairs))
        except (ValueError, TypeError):
            raise SafeError(_RECONCILIATION_FAILURE) from None

    @staticmethod
    def _snapshot_value(value):
        return {'bytes_hex': value.hex()} if type(value) is bytes else value

    def _reconciliation_plan(self, db, operation_hash, legacy_audit=None):
        """Read the exact retained rows; no outside assertion supplies proof.

        The reviewed guarded transport commits its attempt kind, grant debit and
        lifetime debit before every send. For a non-Park, non-navigation action,
        a finished operation with exactly one handshake attempt and a complete
        durable failed-handshake trace therefore has no physical command debit
        or send. HTTP status and authenticated-session success are irrelevant.
        Other shapes remain unknown; missing rows are never evidence of zero.
        """
        self._operation_hash(operation_hash)
        if legacy_audit is not None:
            if (type(legacy_audit) is not LegacyReservationAudit
                    or legacy_audit.provenance_reviewed is not True
                    or legacy_audit.profile != 'set_temperature_handshake_only_v1'
                    or any(type(value) is not str or not _HASH.fullmatch(value) for value in (
                        legacy_audit.historical_artifact_sha256, legacy_audit.guard_source_sha256,
                        legacy_audit.atomic_bridge_source_sha256, legacy_audit.historical_audit_sha256))):
                raise SafeError(_RECONCILIATION_FAILURE)
        self._cap(db)
        grant = db.execute('''SELECT * FROM one_action_grants
            WHERE owner_hash=? AND target_hash=? AND key_sha256=?
              AND operation_hash=? AND state='uncertain' ''',
            (self.owner_hash, self.target_hash, self.key, operation_hash)).fetchone()
        if grant is None:
            raise SafeError(_RECONCILIATION_FAILURE)
        names = [row[1] for row in db.execute('PRAGMA table_info(one_action_grants)')]
        g = dict(zip(names, grant))
        if db.execute('''SELECT 1 FROM grant_reconciliations
            WHERE owner_hash=? AND grant_hash=?''',
            (self.owner_hash, g['grant_hash'])).fetchone() is not None:
            raise SafeError(_RECONCILIATION_FAILURE)
        if (g['action'] not in SPECS or type(g['binding']) is not bytes
                or len(g['binding']) != 32 or not _HASH.fullmatch(g['grant_hash'])):
            raise SafeError(_RECONCILIATION_FAILURE)
        snapshot = {'schema': 1, 'reviewed_wire_invariant':
                    'durable_kind_grant_and_lifetime_debit_before_send_v1',
                    'grant': {name: self._snapshot_value(value)
                              for name, value in zip(names, grant)}}
        snapshot['legacy_audit'] = (vars(legacy_audit) if legacy_audit else None)
        tables = {
            'signer_operations': 'SELECT * FROM signer_operations WHERE owner_hash=? AND operation_hash=?',
            'signer_operation_facts': 'SELECT * FROM signer_operation_facts WHERE owner_hash=? AND operation_hash=?',
            'signer_diagnostics': 'SELECT * FROM signer_diagnostics WHERE owner_hash=? AND operation_hash=? ORDER BY sequence',
            'signer_local_transport': 'SELECT * FROM signer_local_transport WHERE owner_hash=? AND operation_hash=?',
            'signer_response_diagnostics': 'SELECT * FROM signer_response_diagnostics WHERE owner_hash=? AND operation_hash=?',
        }
        rows = {}
        for table, query in tables.items():
            present = db.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?',
                                 (table,)).fetchone() is not None
            columns = [row[1] for row in db.execute(f'PRAGMA table_info({table})')] if present else []
            retained = db.execute(query, (self.owner_hash, operation_hash)).fetchall() if present else []
            if len(retained) > 32:
                raise SafeError(_RECONCILIATION_FAILURE)
            rows[table] = [dict(zip(columns, row)) for row in retained]
            snapshot[table] = {'present': present, 'rows': [
                {name: self._snapshot_value(value) for name, value in zip(columns, row)}
                for row in retained]}
        # Malformed retained evidence is a refusal, rather than an invitation to
        # turn raw/private content into a reconciliation artifact.
        diagnostics = []
        for row in rows['signer_diagnostics']:
            value = self._json_evidence(row['evidence'], checked_diagnostic)
            if row['stage'] != value['stage'] or row['kind'] != value['kind']:
                raise SafeError(_RECONCILIATION_FAILURE)
            diagnostics.append(value)
        responses = [self._json_evidence(row['evidence'], checked_diagnostic)
                     for row in rows['signer_response_diagnostics']]
        transports = [self._json_evidence(row['evidence'], checked_local_transport)
                      for row in rows['signer_local_transport']]
        zero = False
        op = rows['signer_operations'][0] if len(rows['signer_operations']) == 1 else None
        if (op is not None and op['mode'] == 'execute' and op['action'] == g['action']
                and op['key_sha256'] == self.key and op['binding'] == g['binding']
                and op['phase'] == 'finished' and type(op['attempts']) is int
                and op['attempts'] == 1 and op['last_kind'] == 'handshake'
                and type(op['data_attempts']) is int and op['data_attempts'] in (0, 1)
                and type(op['generation']) is int and op['generation'] >= 0
                and op['issued'] >= g['issued'] and op['issued'] < op['expires'] <= g['expires']
                and not SPECS[g['action']].requires_park and g['action'] != 'navigation_send'
                and op['state_observed'] is None and not rows['signer_operation_facts']
                and g['reserved_microdollars'] == 1000 + 2000 * op['data_attempts']):
            zero = self._complete_failed_handshake(rows['signer_diagnostics'], diagnostics)
            if legacy_audit is not None:
                # Absence of optional diagnostics proves nothing. Positive exact
                # atomic ledger shape plus reviewed deployed guard provenance is
                # the separate named legacy evidence route; nothing broader.
                zero = (g['action'] == 'set_temperature' and op['data_attempts'] == 0
                        and g['reserved_microdollars'] == 1000
                        and all(value['kind'] in ('operation', 'handshake')
                                and not value['checkpoint_persistence_failed']
                                and not value['local_finalization_failed'] for value in diagnostics + responses))
            if not all(snapshot[table]['present'] for table in tables):
                zero = False
            if len(responses) > 1 or len(transports) > 1:
                zero = False
            if responses and (not diagnostics or responses[0] != diagnostics[-1]) and legacy_audit is None:
                zero = False
            if any(value['exception_type'] == 'python_journal_error' for value in transports):
                zero = False
        # Snapshot contains the exact original enum evidence bytes, not normalized
        # replacements. It also includes monthly ledger rows as audit evidence;
        # reconciliation never changes, refunds, replenishes or reserves usage.
        usage = db.execute('SELECT month,spent FROM usage WHERE owner_hash=? ORDER BY month',
                           (self.owner_hash,)).fetchall()
        snapshot['usage'] = usage
        snapshot['gross_cap_microdollars'] = db.execute(
            'SELECT gross_limit FROM total_budget_caps WHERE owner_hash=?',
            (self.owner_hash,)).fetchone()[0]
        if sum(row[1] for row in usage) < g['reserved_microdollars']:
            zero = False
        raw = canonical(snapshot).decode()
        if len(raw.encode()) > 65536:
            raise SafeError(_RECONCILIATION_FAILURE)
        return GrantReconciliationPlan(self.owner_hash, self.target_hash, self.key,
            operation_hash, g['grant_hash'], hashlib.sha256(raw.encode()).hexdigest(),
            raw, g['action'], zero, legacy_audit)

    @staticmethod
    def _complete_failed_handshake(rows, values):
        if not 4 <= len(values) <= 10:
            return False
        stages = [value['stage'] for value in values]
        progress = ['operation_started', 'reservation_attempted', 'reservation_acknowledged',
                    'http_initiated', 'request_written', 'response_received',
                    'response_validated', 'authenticated_session_ready']
        # Only an exact prefix followed by a durable terminal failure is proof.
        if stages[-1] != 'operation_failed' or stages[:-1] != progress[:len(values)-1]:
            return False
        for index, (row, value) in enumerate(zip(rows, values), 1):
            if (row['sequence'] != index or value['kind'] != ('operation' if index == 1 else 'handshake')
                    or value['checkpoint_persistence_failed'] or value['local_finalization_failed']):
                return False
            prior = index - 1
            if index == len(values):
                # A terminal failure cannot invent an unretained milestone.
                preceding = values[-2]
                if any(value[key] != preceding[key] for key in
                       ('reservation_acknowledged', 'http_initiated', 'request_written',
                        'response_received', 'authenticated_session_ready', 'http_status')):
                    return False
            elif (value['reservation_acknowledged'] != (prior >= 2)
                    or value['http_initiated'] != (prior >= 3)
                    or value['request_written'] != (prior >= 4)
                    or value['response_received'] != (prior >= 5)
                    or value['authenticated_session_ready'] != (prior >= 7)):
                return False
            if index < len(values) and value['exception_type'] != 'none':
                return False
        final = values[-1]
        return (final['exception_type'] != 'none' and final['category'] != 'none'
                and final['failure_stage'] in stages[:-1])

    def plan_reconciliation(self, operation_hash, *, legacy_audit=None):
        """Inert local review, without authorization, reservation or networking.

        Review summary() plus the private exact action/evidence handle. A zero
        plan proves only no physical transmission in this historical operation;
        it does not prove pairing, responsiveness or an authenticated session.
        """
        with self.store.transaction() as db:
            return self._reconciliation_plan(db, operation_hash, legacy_audit)

    def _checked_plan(self, db, plan):
        if type(plan) is not GrantReconciliationPlan:
            raise SafeError(_RECONCILIATION_FAILURE)
        if (plan.owner_hash != self.owner_hash or plan.target_hash != self.target_hash
                or plan.key_sha256 != self.key):
            raise SafeError(_RECONCILIATION_FAILURE)
        current = self._reconciliation_plan(db, plan.operation_hash, plan.legacy_audit)
        if current != plan:
            raise SafeError(_RECONCILIATION_FAILURE)
        return current

    def authorize_reconciliation(self, plan, decision, approval_reference, *,
                                 operator_authorized=False, ttl_seconds=120):
        """Fresh reviewed operator consent, local only; never creates a grant.

        The reference must identify explicit approval of this exact plan and
        decision. Do not call on a general activation/diagnostic approval. Keep
        returned bearer handle private. Expiry/restart never replenish approval.
        """
        if (operator_authorized is not True or type(decision) is not str or decision not in _DECISIONS
                or type(approval_reference) is not str or not 1 <= len(approval_reference) <= 256
                or type(ttl_seconds) not in (int, float) or not 0 < ttl_seconds <= 120):
            raise SafeError(_RECONCILIATION_FAILURE)
        authorization = secrets.token_hex(16)
        with self.store.transaction() as db:
            now = self.store.now(db)
            current = self._checked_plan(db, plan)
            if decision == 'zero_physical_transmission' and not current.zero_physical_transmission_proven:
                raise SafeError(_RECONCILIATION_FAILURE)
            db.execute('''INSERT INTO grant_reconciliation_authorizations VALUES
                (?,?,?,?,?,?,?,?,?,?,?)''',
                (self.owner_hash, digest(authorization), digest(approval_reference),
                 self.target_hash, self.key, current.operation_hash, current.grant_hash,
                 current.evidence_sha256, decision, now, now + ttl_seconds))
        return authorization

    def _preserve_reconciled_originals(self, db):
        # Once a reconciliation exists, preserve all original operation evidence
        # in addition to its immutable snapshot. No uncertainty-to-acceptance edit.
        identities = {'one_action_grants': ('grant_hash', 'operation_hash'),
                      'signer_operations': ('operation_hash',),
                      'signer_operation_facts': ('operation_hash',),
                      'signer_diagnostics': ('operation_hash',),
                      'signer_response_diagnostics': ('operation_hash',),
                      'signer_local_transport': ('operation_hash',)}
        for table, fields in identities.items():
            if db.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?',
                          (table,)).fetchone() is None:
                continue
            for verb in ('INSERT', 'UPDATE', 'DELETE'):
                aliases = ('OLD', 'NEW') if verb == 'UPDATE' else (('OLD',) if verb == 'DELETE' else ('NEW',))
                matches = []
                for alias in aliases:
                    scope = ' OR '.join(f'{alias}.{name}=r.{name}' for name in fields)
                    matches.append(f'({alias}.owner_hash=r.owner_hash AND ({scope}))')
                condition = ' OR '.join(matches)
                # Both OLD and NEW identities matter: UPDATE/INSERT OR REPLACE
                # must not erase retained evidence via a second UNIQUE index.
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS retain_reconciled_{table}_{verb.lower()}
                    BEFORE {verb} ON {table} WHEN EXISTS (
                        SELECT 1 FROM grant_reconciliations AS r WHERE {condition})
                    BEGIN SELECT RAISE(ABORT,'Original reconciled evidence must be retained'); END''')

    def reconcile(self, authorization, plan):
        """One atomic append; no refund, grant mutation, gate change or transport.

        Unknown is terminal for this mechanism and continues to block arm().
        A zero receipt removes only this old grant's new-grant blocker. Its
        original uncertain row, consumed binding and all old denial checks stay.
        Any subsequent physical action needs a separately reviewed fresh grant.
        """
        if type(authorization) is not str or not _GRANT_ID.fullmatch(authorization):
            raise SafeError(_RECONCILIATION_FAILURE)
        with self.store.transaction() as db:
            now = self.store.now(db)
            current = self._checked_plan(db, plan)
            row = db.execute('''SELECT approval_hash,target_hash,key_sha256,operation_hash,
                grant_hash,evidence_sha256,decision,issued,expires
                FROM grant_reconciliation_authorizations
                WHERE owner_hash=? AND authorization_hash=?''',
                (self.owner_hash, digest(authorization))).fetchone()
            if (row is None or not row[7] <= now < row[8]
                    or row[1:6] != (self.target_hash, self.key, current.operation_hash,
                                   current.grant_hash, current.evidence_sha256)
                    or row[6] == 'zero_physical_transmission' and not current.zero_physical_transmission_proven):
                raise SafeError(_RECONCILIATION_FAILURE)
            db.execute('''INSERT INTO grant_reconciliations VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (self.owner_hash, digest(authorization), row[0], self.target_hash, self.key,
                 current.operation_hash, current.grant_hash, current.evidence_sha256,
                 row[6], now, current.snapshot_json))
            self._preserve_reconciled_originals(db)
        return {'recorded': True, 'decision': row[6], 'original_grant_denied': True,
                'new_grant_blocker_resolved': row[6] == 'zero_physical_transmission',
                'creates_execution_authority': False, 'gross_reservation_microdollars': 0}
