"""Private SQLite state: hashes only for approvals/OAuth, atomic usage reservations."""
import contextlib
from contextvars import ContextVar
import hashlib
import hmac
import math
import os
import secrets
import sqlite3
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from .service import SafeError


DEADLINE_POLICY_VERSION = 1
_REQUEST_DEADLINE = ContextVar('private_journal_request_deadline', default=None)
_REQUEST_CANCEL_CHECKS = ContextVar('private_journal_cancel_checks', default=())
_REQUEST_CANCELLED = ContextVar('private_journal_cancelled', default=None)
_REQUEST_SECONDS_MAX = 25.0
_TRANSACTION_SECONDS_MAX = 0.75
_LOCK_WAIT_SECONDS_MAX = 0.25
_DEADLINE_FAILURE = 'Private state request deadline exceeded; outcome unconfirmed; no retry'


def _refuse_deadline():
    latch = _REQUEST_CANCELLED.get()
    if latch is not None:
        latch[0] = True
    raise SafeError(_DEADLINE_FAILURE) from None


def _check_cancelled():
    latch = _REQUEST_CANCELLED.get()
    if latch is None:
        return
    if latch[0]:
        _refuse_deadline()
    for check in _REQUEST_CANCEL_CHECKS.get():
        try:
            value = check()
        except BaseException:
            _refuse_deadline()
        if type(value) is not bool or value:
            _refuse_deadline()


def _remaining(deadline):
    _check_cancelled()
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _refuse_deadline()
    return remaining


def remaining_request_seconds():
    """Return the current thread's remaining request budget, or None if unscoped."""
    return _remaining(_REQUEST_DEADLINE.get())


def check_request_deadline():
    """Refuse an expired internal request before another local or HTTP step."""
    remaining_request_seconds()


@contextlib.contextmanager
def _deadline_scope(seconds, ceiling, cancelled):
    if (type(seconds) not in (int, float) or not math.isfinite(seconds)
            or not 0 < seconds <= ceiling or (cancelled is not None and not callable(cancelled))):
        raise SafeError('Invalid private journal request deadline')
    deadline = time.monotonic() + seconds
    outer = _REQUEST_DEADLINE.get()
    if outer is not None:
        deadline = min(deadline, outer)
    latch = _REQUEST_CANCELLED.get() if outer is not None else [False]
    checks = _REQUEST_CANCEL_CHECKS.get()
    if cancelled is not None:
        checks = checks + (cancelled,)
    deadline_token = _REQUEST_DEADLINE.set(deadline)
    checks_token = _REQUEST_CANCEL_CHECKS.set(checks)
    cancelled_token = _REQUEST_CANCELLED.set(latch)
    try:
        check_request_deadline()
        yield
        check_request_deadline()
    finally:
        _REQUEST_CANCELLED.reset(cancelled_token)
        _REQUEST_CANCEL_CHECKS.reset(checks_token)
        _REQUEST_DEADLINE.reset(deadline_token)


@contextlib.contextmanager
def journal_deadline(seconds=0.75, cancelled=None):
    """Bound one internal request in its actual handling thread.

    Nested scopes cannot extend the deadline. Each scoped SQL transaction is
    further limited to 0.75 seconds; ordinary OAuth transactions are unchanged.
    Expiry after a durable commit remains unconfirmed, never refunded or retried.
    The caller must leave this scope before acknowledging request success.
    Optional cancellation checks must be nonblocking and return an exact bool.
    Cancellation or a check failure stays latched through nested scopes.
    """
    with _deadline_scope(seconds, _REQUEST_SECONDS_MAX, cancelled):
        yield


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class PrivateStore:
    def __init__(self, directory, clock=time.time):
        self.root = Path(directory)
        self.clock = clock
        try:
            info = self.root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise SafeError('State directory must be owner-only and owned by this user')
            self.path = self.root / 'state.sqlite3'
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            os.close(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise SafeError('State database must be owner-only')
            with self.transaction() as db:
                db.executescript('''
                  CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value REAL NOT NULL);
                  CREATE TABLE IF NOT EXISTS approvals (ticket_hash TEXT PRIMARY KEY, binding BLOB NOT NULL, issued REAL NOT NULL, expires REAL NOT NULL);
                  CREATE TABLE IF NOT EXISTS budgets (owner_hash TEXT PRIMARY KEY, monthly_limit INTEGER NOT NULL);
                  CREATE TABLE IF NOT EXISTS usage (owner_hash TEXT, month TEXT, spent INTEGER NOT NULL, PRIMARY KEY(owner_hash,month));
                  CREATE TABLE IF NOT EXISTS total_budget_caps (owner_hash TEXT PRIMARY KEY, gross_limit INTEGER NOT NULL CHECK(gross_limit>=0));
                  CREATE TRIGGER IF NOT EXISTS enforce_total_cap_insert BEFORE INSERT ON usage
                  WHEN EXISTS(SELECT 1 FROM total_budget_caps WHERE owner_hash=NEW.owner_hash)
                  BEGIN
                    SELECT CASE WHEN NEW.spent < COALESCE((SELECT spent FROM usage WHERE owner_hash=NEW.owner_hash AND month=NEW.month),0)
                      OR COALESCE((SELECT SUM(spent) FROM usage WHERE owner_hash=NEW.owner_hash),0)
                         + NEW.spent - COALESCE((SELECT spent FROM usage WHERE owner_hash=NEW.owner_hash AND month=NEW.month),0)
                         > (SELECT gross_limit FROM total_budget_caps WHERE owner_hash=NEW.owner_hash)
                    THEN RAISE(ABORT,'One-time gross allowance exhausted or ledger decrease refused') END;
                  END;
                  CREATE TRIGGER IF NOT EXISTS enforce_total_cap_update BEFORE UPDATE OF spent ON usage
                  WHEN EXISTS(SELECT 1 FROM total_budget_caps WHERE owner_hash=NEW.owner_hash)
                  BEGIN
                    SELECT CASE WHEN NEW.spent < OLD.spent
                      OR COALESCE((SELECT SUM(spent) FROM usage WHERE owner_hash=NEW.owner_hash),0) + NEW.spent - OLD.spent
                         > (SELECT gross_limit FROM total_budget_caps WHERE owner_hash=NEW.owner_hash)
                    THEN RAISE(ABORT,'One-time gross allowance exhausted or ledger decrease refused') END;
                  END;
                  CREATE TRIGGER IF NOT EXISTS preserve_total_cap_usage BEFORE DELETE ON usage
                  WHEN EXISTS(SELECT 1 FROM total_budget_caps WHERE owner_hash=OLD.owner_hash)
                  BEGIN SELECT RAISE(ABORT,'One-time gross allowance ledger must be retained'); END;
                  CREATE TABLE IF NOT EXISTS oauth_states (state_hash TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, session_hash TEXT NOT NULL, nonce_hash TEXT NOT NULL, scopes TEXT NOT NULL, expires REAL NOT NULL);
                  CREATE TABLE IF NOT EXISTS refresh_state (owner_hash TEXT PRIMARY KEY, status TEXT NOT NULL, generation INTEGER NOT NULL);
                ''')
        except (OSError, sqlite3.Error):
            raise SafeError('Private state unavailable') from None

    @contextlib.contextmanager
    def transaction(self):
        db = None
        request_deadline = _REQUEST_DEADLINE.get()
        deadline = None
        if request_deadline is not None:
            check_request_deadline()
            deadline = min(request_deadline, time.monotonic() + _TRANSACTION_SECONDS_MAX)

        def bounded_wait():
            remaining = _remaining(deadline)
            if remaining is not None:
                # SQLite's busy handler is separate from its progress handler.
                # Recalculate before COMMIT so lock waiting cannot use old time.
                db.execute('PRAGMA busy_timeout=' + str(int(1000 * min(_LOCK_WAIT_SECONDS_MAX, remaining))))

        def rollback():
            if db is not None:
                # An expired progress callback must not interrupt cleanup. A
                # completed COMMIT has no active transaction to roll back.
                db.set_progress_handler(None, 0)
                if db.in_transaction:
                    db.rollback()

        def interrupted():
            try:
                _remaining(deadline)
                return 0
            except SafeError:
                return 1

        try:
            timeout = 15 if deadline is None else min(_LOCK_WAIT_SECONDS_MAX, _remaining(deadline))
            db = sqlite3.connect(self.path, timeout=timeout, isolation_level=None)
            if deadline is not None:
                db.set_progress_handler(interrupted, 1000)
                bounded_wait()
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            bounded_wait()
            db.execute('BEGIN IMMEDIATE')
            _remaining(deadline)
            yield db
            bounded_wait()
            _remaining(deadline)
            db.commit()
            # FULL fsync may complete after the pre-COMMIT check. The reservation
            # remains durable, but the request must not acknowledge it as timely.
            _remaining(deadline)
        except sqlite3.Error:
            rollback()
            raise SafeError('Private state transaction failed') from None
        except BaseException:
            rollback()
            raise
        finally:
            if db is not None:
                db.set_progress_handler(None, 0)
                db.close()

    def now(self, db):
        value = self.clock()
        if type(value) not in (int, float) or not 0 < value < 1e12:
            raise SafeError('Invalid state clock')
        row = db.execute("SELECT value FROM meta WHERE key='clock_high_water'").fetchone()
        if row and value < row[0]:
            raise SafeError('Clock rollback detected; state operations blocked')
        db.execute("INSERT INTO meta VALUES ('clock_high_water',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (value,))
        return value


class DurableApprovalLedger:
    def __init__(self, store):
        self.store = store

    def approve(self, intent, ttl=60):
        if type(ttl) not in (int, float) or not 0 < ttl <= 120:
            raise SafeError('Approval lifetime must be at most 120 seconds')
        binding = intent.binding()
        ticket = secrets.token_hex(32)
        with self.store.transaction() as db:
            now = self.store.now(db)
            db.execute('DELETE FROM approvals WHERE expires<=?', (now,))
            if db.execute('SELECT count(*) FROM approvals').fetchone()[0] >= 128:
                raise SafeError('Approval capacity reached')
            db.execute('INSERT INTO approvals VALUES (?,?,?,?)', (digest(ticket), binding, now, now + ttl))
        return ticket

    def consume(self, ticket, intent):
        binding = intent.binding()
        if not isinstance(ticket, str) or len(ticket) != 64 or any(c not in '0123456789abcdef' for c in ticket):
            raise SafeError('Approval missing or invalid')
        valid = False
        with self.store.transaction() as db:
            now = self.store.now(db)
            grant = db.execute('SELECT binding,issued,expires FROM approvals WHERE ticket_hash=?', (digest(ticket),)).fetchone()
            db.execute('DELETE FROM approvals WHERE ticket_hash=?', (digest(ticket),))
            valid = grant is not None and grant[1] <= now < grant[2] and hmac.compare_digest(binding, grant[0])
        # Reject AFTER commit so a mismatch/expiry burns the record durably.
        if not valid:
            raise SafeError('Approval expired, consumed or mismatched')


class DurableBudget:
    RATES = {'data': 2000, 'commands': 1000}  # Microdollars: gross published unit rates.

    def __init__(self, store, owner):
        if not isinstance(owner, str) or not owner:
            raise SafeError('Budget owner required')
        self.store, self.owner = store, digest(owner)

    def configure(self, monthly_microdollars):
        # Trusted operator-only API; not an MCP tool. Missing policy means zero allowance.
        if type(monthly_microdollars) is not int or not 0 <= monthly_microdollars <= 10_000_000:
            raise SafeError('Invalid gross monthly budget')
        with self.store.transaction() as db:
            db.execute('INSERT INTO budgets VALUES (?,?) ON CONFLICT(owner_hash) DO UPDATE SET monthly_limit=excluded.monthly_limit', (self.owner, monthly_microdollars))

    def configure_total(self, gross_microdollars):
        """Operator-only one-time cap, including all retained prior reservations.

        SQLite triggers also constrain already-running budget instances; no
        process restart or month rollover can replenish this approved cap.
        """
        if type(gross_microdollars) is not int or not 0 <= gross_microdollars <= 10_000_000:
            raise SafeError('Invalid one-time gross allowance')
        with self.store.transaction() as db:
            total = db.execute('SELECT COALESCE(SUM(spent),0) FROM usage WHERE owner_hash=?', (self.owner,)).fetchone()[0]
            if total > gross_microdollars:
                raise SafeError('One-time allowance below already reserved usage')
            db.execute('INSERT INTO total_budget_caps VALUES (?,?) ON CONFLICT(owner_hash) DO UPDATE SET gross_limit=excluded.gross_limit', (self.owner, gross_microdollars))
            db.execute('INSERT INTO budgets VALUES (?,?) ON CONFLICT(owner_hash) DO UPDATE SET monthly_limit=excluded.monthly_limit', (self.owner, gross_microdollars))

    def total_status(self):
        with self.store.transaction() as db:
            limit = db.execute('SELECT gross_limit FROM total_budget_caps WHERE owner_hash=?', (self.owner,)).fetchone()
            spent = db.execute('SELECT COALESCE(SUM(spent),0) FROM usage WHERE owner_hash=?', (self.owner,)).fetchone()[0]
            return {'configured':limit is not None, 'cap_microdollars':limit[0] if limit else 0,
                    'reserved_microdollars':spent, 'remaining_microdollars':max(0,limit[0]-spent) if limit else 0}

    def reserve(self, category):
        with self.store.transaction() as db:
            self._reserve_in_transaction(db, category)
        # Reserve before attempt, never refund uncertain/errors. No rates/credit guarantee.

    def _reserve_in_transaction(self, db, category):
        """Trusted bridge journals exact attempt and usage in the same transaction."""
        if category not in self.RATES:
            raise SafeError('Budget category not allowed')
        now = self.store.now(db)
        month = datetime.fromtimestamp(now, timezone.utc).strftime('%Y-%m')
        limit = db.execute('SELECT monthly_limit FROM budgets WHERE owner_hash=?', (self.owner,)).fetchone()
        used = db.execute('SELECT spent FROM usage WHERE owner_hash=? AND month=?', (self.owner, month)).fetchone()
        spent = used[0] if used else 0
        if not limit or spent + self.RATES[category] > limit[0]:
            raise SafeError('Gross monthly budget exhausted or not configured')
        db.execute('INSERT INTO usage VALUES (?,?,?) ON CONFLICT(owner_hash,month) DO UPDATE SET spent=excluded.spent', (self.owner, month, spent + self.RATES[category]))

    def spent(self):
        with self.store.transaction() as db:
            month = datetime.fromtimestamp(self.store.now(db), timezone.utc).strftime('%Y-%m')
            row = db.execute('SELECT spent FROM usage WHERE owner_hash=? AND month=?', (self.owner, month)).fetchone()
            return row[0] if row else 0
