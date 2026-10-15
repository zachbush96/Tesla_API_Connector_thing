"""Only temporary SQLite files; no runtime, credential or network access."""
import concurrent.futures
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tesla_connector import storage
from tesla_connector.service import SafeError
from tesla_connector.storage import (DurableBudget, PrivateStore, check_request_deadline,
                              journal_deadline, remaining_request_seconds)


class StorageDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        root.chmod(0o700)
        self.store = PrivateStore(root)
        self.budget = DurableBudget(self.store, 'synthetic-owner')
        self.budget.configure_total(100000)
        with self.store.transaction() as db:
            db.execute('CREATE TABLE test_attempts (operation TEXT PRIMARY KEY)')

    def reserve(self, db):
        self.budget._reserve_in_transaction(db, 'commands')
        db.execute('INSERT INTO test_attempts VALUES (?)', ('synthetic-once',))

    def retained(self):
        with self.store.transaction() as db:
            return (db.execute('SELECT COALESCE(SUM(spent),0) FROM usage').fetchone()[0],
                    db.execute('SELECT operation FROM test_attempts').fetchall())

    def test_sqlite_writer_lock_wait_is_short_and_does_not_reserve(self):
        blocker = sqlite3.connect(self.store.path, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute('BEGIN IMMEDIATE')
        started = time.monotonic()
        try:
            with self.assertRaises(SafeError):
                with journal_deadline(1):
                    with self.store.transaction() as db:
                        self.reserve(db)
        finally:
            blocker.rollback()
        self.assertLess(time.monotonic() - started, .7)
        self.assertEqual(self.retained(), (0, []))

    def test_delayed_body_cannot_commit_usage_or_attempt(self):
        entered = False
        with self.assertRaises(SafeError):
            with journal_deadline(.1):
                with self.store.transaction() as db:
                    self.reserve(db)
                    entered = True
                    time.sleep(.12)
        self.assertTrue(entered)
        self.assertEqual(self.retained(), (0, []))

    def test_long_sql_is_interrupted_and_rolls_back_pending_reservation(self):
        started = time.monotonic()
        with self.assertRaises(SafeError):
            with journal_deadline(.1):
                with self.store.transaction() as db:
                    self.reserve(db)
                    db.execute('''WITH RECURSIVE count(n) AS
                        (VALUES(0) UNION ALL SELECT n+1 FROM count WHERE n<100000000)
                        SELECT SUM(n) FROM count''').fetchone()
        self.assertLess(time.monotonic() - started, .8)
        self.assertEqual(self.retained(), (0, []))

    def test_claim_scope_still_caps_each_transaction_at_point_seven_five(self):
        clock = [100.0]
        with patch.object(storage.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(SafeError):
                with journal_deadline(25):
                    with self.store.transaction() as db:
                        self.reserve(db)
                        clock[0] += .8
        self.assertEqual(self.retained(), (0, []))

    def test_late_durable_commit_is_unconfirmed_without_refund(self):
        clock = [100.0]
        connect = sqlite3.connect

        class LateCommit:
            def __init__(self, delegate):
                self.delegate = delegate

            def __getattr__(self, name):
                return getattr(self.delegate, name)

            def commit(self):
                self.delegate.commit()
                clock[0] += 1

        with patch.object(storage.time, 'monotonic', side_effect=lambda: clock[0]):
            with patch.object(storage.sqlite3, 'connect',
                              side_effect=lambda *a, **kw: LateCommit(connect(*a, **kw))):
                with self.assertRaisesRegex(SafeError, 'outcome unconfirmed; no retry'):
                    with journal_deadline(25):
                        with self.store.transaction() as db:
                            self.reserve(db)
        self.assertEqual(self.retained(), (1000, [('synthetic-once',)]))

    def test_nested_scope_cannot_extend_and_exception_restores_default_policy(self):
        clock = [100.0]
        with patch.object(storage.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(SafeError):
                with journal_deadline(.1):
                    with journal_deadline(25):
                        clock[0] += .2
                        check_request_deadline()
        self.assertIsNone(remaining_request_seconds())
        with self.store.transaction() as db:
            self.assertEqual(db.execute('PRAGMA busy_timeout').fetchone(), (15000,))
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone(), ('delete',))
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone(), (2,))
        with journal_deadline(25):
            with self.store.transaction() as db:
                self.assertLessEqual(db.execute('PRAGMA busy_timeout').fetchone()[0], 250)

    def test_peer_cancellation_prevents_commit_and_stays_latched(self):
        disconnected = [False]
        with self.assertRaises(SafeError):
            with journal_deadline(25, cancelled=lambda: disconnected[0]):
                try:
                    with self.store.transaction() as db:
                        self.reserve(db)
                        disconnected[0] = True
                except SafeError:
                    disconnected[0] = False
                    check_request_deadline()
        self.assertEqual(self.retained(), (0, []))
        self.assertIsNone(remaining_request_seconds())

    def test_nested_cancellation_cannot_be_cleared_by_leaving_child_scope(self):
        with self.assertRaises(SafeError):
            with journal_deadline(25):
                try:
                    with journal_deadline(1, cancelled=lambda: True):
                        self.fail('Canceled scope must not enter')
                except SafeError:
                    pass
                check_request_deadline()
        self.assertIsNone(remaining_request_seconds())

    def test_callback_failure_or_nonboolean_result_refuses_without_details(self):
        def broken():
            raise RuntimeError('synthetic withheld detail')
        for callback in (broken, lambda: 'wrong-type'):
            with self.subTest(callback=callback):
                with self.assertRaises(SafeError) as failure:
                    with journal_deadline(1, cancelled=callback):
                        self.fail('Unsafe cancellation check must not enter')
                self.assertNotIn('synthetic withheld detail', str(failure.exception))
        self.assertIsNone(remaining_request_seconds())

    def test_context_is_not_inherited_by_an_unwrapped_worker_thread(self):
        with journal_deadline(1):
            self.assertGreater(remaining_request_seconds(), 0)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                self.assertIsNone(worker.submit(remaining_request_seconds).result(timeout=1))

    def test_invalid_scope_bounds_are_refused(self):
        for seconds in (True, 0, -1, 25.1, float('inf'), float('nan')):
            with self.subTest(seconds=seconds), self.assertRaises(SafeError):
                with journal_deadline(seconds):
                    self.fail('Invalid scope must not enter')
        with self.assertRaises(SafeError):
            with journal_deadline(1, cancelled=False):
                self.fail('Invalid callback must not enter')


if __name__ == '__main__':
    unittest.main()
