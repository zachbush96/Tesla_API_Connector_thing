"""One-action grant tests: synthetic private databases and no transports."""
import concurrent.futures
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tesla_connector.controls import ControlIntent
from tesla_connector.execution_grants import OneActionGrants
from tesla_connector.service import SafeError
from tesla_connector.storage import DurableBudget, PrivateStore, digest


OWNER = 'synthetic-grant-owner'
TARGET = 'AAAAAAAAAAAAAAAAA'
KEY = 'a' * 64


class ExecutionGrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        Path(self.temp.name).chmod(0o700)
        self.now = 1700000000.
        self.store = PrivateStore(self.temp.name, clock=lambda: self.now)
        self.budget = DurableBudget(self.store, OWNER)
        self.budget.configure_total(100000)
        # Retained prior usage must remain in the same lifetime ledger.
        for _ in range(7):
            self.budget.reserve('commands')
        self.grants = OneActionGrants(OWNER, TARGET, KEY, self.budget)
        self.intent = ControlIntent.build(OWNER, TARGET, 'set_temperature', {'celsius':20})
        self.operation = digest('synthetic-operation')

    def state(self):
        with self.store.transaction() as db:
            return db.execute('''SELECT state,operation_hash,reserved_microdollars,
                max_gross_microdollars,expires,issued FROM one_action_grants
                ORDER BY issued,grant_hash''').fetchall()

    def consume(self, operation=None, intent=None, grants=None):
        with self.store.transaction() as db:
            return (grants or self.grants).consume(
                db, operation or self.operation, (intent or self.intent).binding())

    def reserve(self, amount, category, operation=None):
        with self.store.transaction() as db:
            self.grants.reserve(db, operation or self.operation, amount)
            self.budget._reserve_in_transaction(db, category)

    def finish(self, accepted=False):
        with self.store.transaction() as db:
            self.grants.finish(db, self.operation, accepted=accepted)

    def test_arming_is_inert_and_exact_twenty_degree_binding_is_hashed(self):
        grant = self.grants.arm(self.intent, 5000)
        with self.store.transaction() as db:
            row = db.execute('''SELECT owner_hash,grant_hash,target_hash,key_sha256,
                binding,action,state,operation_hash FROM one_action_grants''').fetchone()
        self.assertEqual(row, (digest(OWNER),digest(grant),digest(TARGET),KEY,
                               self.intent.binding(),'set_temperature','armed',None))
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)
        contents = self.store.path.read_bytes()
        self.assertNotIn(OWNER.encode(),contents)
        self.assertNotIn(TARGET.encode(),contents)
        self.assertNotIn(grant.encode(),contents)
        self.assertNotIn(self.intent.payload_json,contents)

    def test_unarmed_operation_has_no_authority_or_cost(self):
        with self.assertRaises(SafeError):
            self.consume()
        self.assertEqual(self.state(),[])
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_grant_can_be_consumed_once_and_cannot_authorize_another_operation(self):
        grant = self.grants.arm(self.intent,5000)
        grant_hash, expiry = self.consume()
        self.assertEqual(grant_hash,digest(grant))
        self.assertEqual(expiry,self.now+300)
        for operation in (self.operation,digest('different-operation')):
            with self.assertRaises(SafeError):
                self.consume(operation=operation)
        self.assertEqual(self.state()[0][:3],('consumed',self.operation,0))

    def test_wrong_payload_action_vehicle_owner_and_key_are_refused(self):
        self.grants.arm(self.intent,5000)
        changed = [
            ControlIntent.build(OWNER,TARGET,'set_temperature',{'celsius':21}),
            ControlIntent.build(OWNER,TARGET,'climate_start',{}),
            ControlIntent.build(OWNER,'BBBBBBBBBBBBBBBBB','set_temperature',{'celsius':20}),
            ControlIntent.build('another-owner',TARGET,'set_temperature',{'celsius':20}),
        ]
        for intent in changed:
            with self.subTest(action=intent.action,owner=intent.principal,target=intent.target):
                with self.assertRaises(SafeError):
                    self.consume(intent=intent)
        different_key = OneActionGrants(OWNER,TARGET,'b'*64,self.budget)
        with self.assertRaises(SafeError):
            self.consume(grants=different_key)
        self.assertEqual(self.state()[0][0],'armed')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_invalid_identity_key_allowance_ttl_and_binding_fail_closed(self):
        for owner,target,key in [('',TARGET,KEY),(OWNER,'bad',KEY),(OWNER,TARGET,'bad'),
                                ('another-owner',TARGET,KEY)]:
            with self.subTest(owner=owner,target=target,key_valid=key==KEY):
                with self.assertRaises(SafeError):
                    OneActionGrants(owner,target,key,self.budget)
        for amount in (0,-1,True,5000.,5001,6000):
            with self.subTest(amount=amount):
                with self.assertRaises(SafeError):
                    self.grants.arm(self.intent,amount)
        for ttl in (0,-1,True,301,float('nan'),float('inf'),'300'):
            with self.subTest(ttl=ttl):
                with self.assertRaises(SafeError):
                    self.grants.arm(self.intent,5000,ttl_seconds=ttl)
        other = ControlIntent.build('another-owner',TARGET,'set_temperature',{'celsius':20})
        with self.assertRaises(SafeError):
            self.grants.arm(other,5000)
        self.grants.arm(self.intent,5000)
        for operation,binding in [('not-hash',self.intent.binding()),
                                  (self.operation,'a'*64),(self.operation,b'bad')]:
            with self.store.transaction() as db:
                with self.assertRaises(SafeError):
                    self.grants.consume(db,operation,binding)

    def test_security_action_has_a_separate_bounded_ceiling(self):
        security = ControlIntent.build(OWNER,TARGET,'lock',{})
        with self.assertRaises(SafeError):
            self.grants.arm(security,6001)
        self.grants.arm(security,6000)
        self.assertEqual(self.state()[0][3],6000)

    def test_exact_expiry_and_expired_unconsumed_replacement(self):
        self.grants.arm(self.intent,5000,ttl_seconds=5)
        self.now += 5
        with self.assertRaises(SafeError):
            self.consume()
        self.grants.arm(self.intent,5000,ttl_seconds=300)
        states = [row[0] for row in self.state()]
        self.assertEqual(states.count('revoked'),1)
        self.assertEqual(states.count('armed'),1)
        self.consume()

    def test_consumed_expiry_blocks_attempts_and_new_arming_indefinitely(self):
        self.grants.arm(self.intent,5000,ttl_seconds=5)
        self.consume()
        self.now += 500
        with self.store.transaction() as db:
            with self.assertRaises(SafeError):
                self.grants.validate(db,self.operation)
        with self.assertRaises(SafeError):
            self.reserve(1000,'commands')
        with self.assertRaises(SafeError):
            self.grants.arm(self.intent,5000)
        self.assertEqual(self.state()[0][0],'consumed')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_restart_retains_armed_binding_and_consumed_replay_rejection(self):
        self.grants.arm(self.intent,5000)
        restarted_store = PrivateStore(self.temp.name,clock=lambda:self.now)
        restarted_budget = DurableBudget(restarted_store,OWNER)
        restarted = OneActionGrants(OWNER,TARGET,KEY,restarted_budget)
        with restarted_store.transaction() as db:
            restarted.consume(db,self.operation,self.intent.binding())
        with self.assertRaises(SafeError):
            self.consume()
        with self.assertRaises(SafeError):
            restarted.arm(self.intent,5000)
        self.assertEqual(restarted_budget.total_status()['reserved_microdollars'],7000)

    def test_concurrent_operations_have_exactly_one_winner(self):
        self.grants.arm(self.intent,5000)
        def attempt(index):
            try:
                self.consume(operation=digest('synthetic-concurrent-'+str(index)))
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt,range(16)))
        self.assertEqual(sum(results),1)
        self.assertEqual(len(self.state()),1)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_concurrent_arming_across_keys_has_exactly_one_winner(self):
        def attempt(index):
            other = OneActionGrants(OWNER,TARGET,('a' if index%2 else 'b')*64,self.budget)
            try:
                other.arm(self.intent,5000)
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt,range(16)))
        self.assertEqual(sum(results),1)
        self.assertEqual(len(self.state()),1)

    def test_consumption_and_operation_registration_rollback_together(self):
        self.grants.arm(self.intent,5000)
        with self.store.transaction() as db:
            db.execute('CREATE TABLE synthetic_operations (operation_hash TEXT PRIMARY KEY)')
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as db:
                self.grants.consume(db,self.operation,self.intent.binding())
                db.execute('INSERT INTO synthetic_operations VALUES(?)',(self.operation,))
                raise RuntimeError('synthetic failure before commit')
        self.assertEqual(self.state()[0][:3],('armed',None,0))
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM synthetic_operations').fetchone()[0],0)
        self.consume()

    def test_bounded_preflight_and_three_signed_attempts_retain_prior_usage(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        self.reserve(2000,'data')
        for _ in range(3):
            self.reserve(1000,'commands')
        self.assertEqual(self.state()[0][2:4],(5000,5000))
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],12000)
        self.assertEqual(self.budget.total_status()['remaining_microdollars'],88000)
        with self.assertRaises(SafeError):
            self.reserve(1000,'commands')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],12000)

    def test_simultaneous_reservations_cannot_exceed_grant(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        def attempt(_):
            try:
                self.reserve(1000,'commands')
                return True
            except SafeError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt,range(12)))
        self.assertEqual(sum(results),5)
        self.assertEqual(self.state()[0][2],5000)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],12000)

    def test_grant_and_lifetime_reservation_rollback_together(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as db:
                self.grants.reserve(db,self.operation,2000)
                self.budget._reserve_in_transaction(db,'data')
                raise RuntimeError('synthetic failure before outgoing attempt')
        self.assertEqual(self.state()[0][2],0)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_failed_lifetime_debit_does_not_partially_debit_grant(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        self.budget.configure(7000)
        with self.assertRaises(SafeError):
            self.reserve(1000,'commands')
        self.assertEqual(self.state()[0][2],0)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_full_grant_headroom_required_at_arm_and_consume(self):
        self.budget.configure_total(11999)
        with self.assertRaises(SafeError):
            self.grants.arm(self.intent,5000)
        self.assertEqual(self.state(),[])
        self.budget.configure_total(12000)
        self.grants.arm(self.intent,5000)
        self.budget.reserve('commands')
        with self.assertRaises(SafeError):
            self.consume()
        self.assertEqual(self.state()[0][0],'armed')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],8000)

    def test_absent_or_over_one_tenth_dollar_cap_refused_without_changing_cap(self):
        for cap in (0,100001):
            self.budget.configure_total(cap) if cap else None
            with self.store.transaction() as db:
                if not cap:
                    db.execute('DELETE FROM total_budget_caps WHERE owner_hash=?',(self.budget.owner,))
            with self.assertRaises(SafeError):
                self.grants.arm(self.intent,5000)
        self.assertEqual(self.budget.total_status()['cap_microdollars'],100001)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_crash_after_commit_blocks_replay_new_grant_and_changed_key(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        self.reserve(1000,'commands')
        # No finish: simulate process loss after durable consumption/reservation.
        restarted = OneActionGrants(OWNER,TARGET,'b'*64,self.budget)
        with self.assertRaises(SafeError):
            restarted.arm(self.intent,5000)
        with self.store.transaction() as db:
            with self.assertRaises(SafeError):
                restarted.validate(db,self.operation)
        with self.assertRaises(SafeError):
            self.consume()
        self.assertEqual(self.state()[0][2],1000)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],8000)

    def test_uncertainty_is_irreversible_across_expiry_restart_or_late_receipt(self):
        grant = self.grants.arm(self.intent,5000)
        self.consume()
        self.finish()
        self.now += 1000
        self.finish(accepted=True)
        restarted = OneActionGrants(OWNER,TARGET,KEY,self.budget)
        with self.assertRaises(SafeError):
            restarted.arm(self.intent,5000)
        with self.assertRaises(SafeError):
            restarted.revoke(grant)
        self.assertEqual(self.state()[0][0],'uncertain')

    def test_accepted_submission_is_terminal_but_never_replays(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        self.reserve(1000,'commands')
        self.finish(accepted=True)
        self.finish(accepted=False)
        with self.store.transaction() as db:
            with self.assertRaises(SafeError):
                self.grants.validate(db,self.operation)
        with self.assertRaises(SafeError):
            self.consume()
        self.assertEqual(self.state()[0][0],'accepted')
        self.grants.arm(self.intent,5000)
        self.assertEqual(len(self.state()),2)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],8000)

    def test_revoke_only_unused_grant_and_never_consumed_uncertainty(self):
        grant = self.grants.arm(self.intent,5000)
        self.grants.revoke(grant)
        with self.assertRaises(SafeError):
            self.consume()
        self.assertEqual(self.state()[0][0],'revoked')
        second = self.grants.arm(self.intent,5000)
        self.consume()
        with self.assertRaises(SafeError):
            self.grants.revoke(second)
        self.assertEqual(sorted(row[0] for row in self.state()),['consumed','revoked'])

    def test_clock_rollback_never_rearms_or_spends(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        self.now -= 1
        for operation in (lambda:self.consume(), lambda:self.reserve(1000,'commands'),
                          lambda:self.grants.arm(self.intent,5000),lambda:self.finish(True)):
            with self.assertRaises(SafeError):
                operation()
        self.now += 1
        self.assertEqual(self.state()[0][0],'consumed')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_unknown_operation_and_invalid_amount_cannot_spend(self):
        self.grants.arm(self.intent,5000)
        self.consume()
        with self.assertRaises(SafeError):
            self.reserve(1000,'commands',operation=digest('unknown'))
        for amount in (True,0,-1,1000.,3000):
            with self.subTest(amount=amount):
                with self.assertRaises(SafeError):
                    self.reserve(amount,'commands')
        self.assertEqual(self.state()[0][2],0)
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def navigation_intent(self):
        with patch('tesla_connector.service.time.time', return_value=self.now):
            return ControlIntent.build(OWNER,TARGET,'navigation_send',
                                       {'destination':'Synthetic private destination'})

    def test_navigation_preparation_reuses_approved_timestamp_after_clock_changes(self):
        original = self.navigation_intent()
        self.grants.arm(original,5000)
        self.now += 10
        with patch('tesla_connector.service.time.time', return_value=self.now):
            prepared = self.grants.prepare_intent('navigation_send',
                {'destination':'Synthetic private destination'})
            regenerated = ControlIntent.build(OWNER,TARGET,'navigation_send',
                {'destination':'Synthetic private destination'})
        self.assertEqual(prepared,original)
        self.assertEqual(prepared.binding(),original.binding())
        self.assertNotEqual(regenerated.binding(),original.binding())
        self.assertEqual(self.state()[0][0],'armed')
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT navigation_timestamp_ms FROM one_action_grants').fetchone()[0],
                             '1700000000000')
        self.assertNotIn(b'Synthetic private destination',self.store.path.read_bytes())
        self.consume(intent=prepared)

    def test_navigation_wrong_destination_key_expiry_and_consumption_refused(self):
        original = self.navigation_intent()
        self.grants.arm(original,5000,ttl_seconds=5)
        with self.assertRaises(SafeError):
            self.grants.prepare_intent('navigation_send',{'destination':'Different destination'})
        changed = OneActionGrants(OWNER,TARGET,'b'*64,self.budget)
        with self.assertRaises(SafeError):
            changed.prepare_intent('navigation_send',{'destination':'Synthetic private destination'})
        self.now += 5
        with self.assertRaises(SafeError):
            self.grants.prepare_intent('navigation_send',{'destination':'Synthetic private destination'})
        self.grants.arm(original,5000)
        self.consume(intent=original)
        with self.assertRaises(SafeError):
            self.grants.prepare_intent('navigation_send',{'destination':'Synthetic private destination'})
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)

    def test_navigation_legacy_missing_timestamp_is_migrated_and_fails_closed(self):
        original = self.navigation_intent()
        self.grants.arm(original,5000)
        with self.store.transaction() as db:
            db.execute('ALTER TABLE one_action_grants DROP COLUMN navigation_timestamp_ms')
        restarted = OneActionGrants(OWNER,TARGET,KEY,self.budget)
        with self.store.transaction() as db:
            columns = {row[1] for row in db.execute('PRAGMA table_info(one_action_grants)')}
            self.assertIn('navigation_timestamp_ms',columns)
        with self.assertRaises(SafeError):
            restarted.prepare_intent('navigation_send',{'destination':'Synthetic private destination'})
        self.assertEqual(self.state()[0][0],'armed')

    def test_non_navigation_preparation_is_inert_without_a_grant(self):
        self.assertEqual(self.grants.prepare_intent('set_temperature',{'celsius':20}),self.intent)
        self.assertEqual(self.state(),[])
        with self.assertRaises(SafeError):
            self.grants.prepare_intent('navigation_send',{'destination':'Synthetic private destination'})
        self.assertEqual(self.budget.total_status()['reserved_microdollars'],7000)


if __name__ == '__main__':
    unittest.main()
