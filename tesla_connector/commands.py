"""Setup-ready command/approval core, exercised only with mock transports.

Only a trusted operator broker may call ApprovalLedger.approve. It is deliberately
absent from MCP tools. A production broker needs isolation from the model process.
"""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.request
from dataclasses import dataclass
from .service import SafeError, command_plan, navigation_payload


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@dataclass(frozen=True, repr=False)
class Intent:
    principal: str
    target: str
    command: str
    payload_json: bytes

    @classmethod
    def build(cls, principal, target, name, args):
        if not isinstance(principal, str) or not principal or len(principal) > 256:
            raise SafeError('Invalid trusted principal')
        if not isinstance(target, str) or not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}', target):
            raise SafeError('Invalid configured vehicle')
        command, payload = command_plan(name, args)
        return cls(principal, target, command, canonical(payload))

    def validated(self):
        # Revalidate even manually constructed intents; no arbitrary POST path or payload.
        try:
            payload = json.loads(self.payload_json)
            if self.command == 'set_temps':
                if set(payload) != {'driver_temp', 'passenger_temp'} or payload['driver_temp'] != payload['passenger_temp']:
                    raise SafeError('Command not allowed')
                args = {'celsius': payload['driver_temp']}
                name = 'preview_temperature'
            elif self.command == 'navigation_request':
                if not isinstance(payload, dict) or set(payload) != {'type', 'value', 'locale', 'timestamp_ms'}:
                    raise SafeError('Command not allowed')
                if not isinstance(payload['value'], dict) or set(payload['value']) != {'android.intent.ACTION', 'android.intent.TYPE', 'android.intent.TEXT', 'android.intent.extra.TEXT'}:
                    raise SafeError('Command not allowed')
                rebuilt = navigation_payload(payload['value']['android.intent.TEXT'], payload['timestamp_ms'])
                if canonical(rebuilt) != self.payload_json:
                    raise SafeError('Noncanonical navigation payload')
                # Preserve the exact server-created timestamp in the approval binding.
                self.build(self.principal, self.target, 'preview_navigation', {'destination': payload['value']['android.intent.TEXT']})
                return self
            else:
                raise SafeError('Command not allowed')
            valid = self.build(self.principal, self.target, name, args)
            if valid.payload_json != self.payload_json:
                raise SafeError('Noncanonical command payload')
            return valid
        except (ValueError, TypeError, KeyError):
            raise SafeError('Command not allowed') from None

    def binding(self):
        self.validated()
        return hashlib.sha256(canonical({'version': 1, 'principal': self.principal,
                              'target': self.target, 'command': self.command,
                              'payload': self.payload_json.decode()})).digest()


class ApprovalLedger:
    """Volatile, single-process, one-use approvals; restart invalidates every grant.

    A monotonic clock avoids wall-clock rollback. Lock covers approval consumption,
    so two simultaneous submissions cannot use the same approval. Capacity bounded.
    """
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._grants = {}
        self._lock = threading.Lock()

    def approve(self, intent, ttl=60):
        # Invoke only after a human sees the exact intent in a trusted operator UI.
        if type(ttl) not in (int, float) or not 0 < ttl <= 120:
            raise SafeError('Approval lifetime must be at most 120 seconds')
        binding = intent.binding()
        with self._lock:
            now = self._clock()
            self._grants = {key: val for key, val in self._grants.items() if val[1] > now}
            if len(self._grants) >= 128:
                raise SafeError('Approval capacity reached')
            ticket = secrets.token_hex(32)
            self._grants[ticket] = (binding, now + ttl, now)
            return ticket

    def consume(self, ticket, intent):
        binding = intent.binding()
        if not isinstance(ticket, str) or not re.fullmatch(r'[0-9a-f]{64}', ticket):
            raise SafeError('Approval missing or invalid')
        with self._lock:
            grant = self._grants.pop(ticket, None)  # Burn even on mismatch/failure.
            now = self._clock()
            if grant is None or now < grant[2] or now >= grant[1] or not hmac.compare_digest(binding, grant[0]):
                raise SafeError('Approval expired, consumed or mismatched')


class DisabledNetwork:
    """Permanent runtime kill switch. No environment variable enables live commands."""
    simulated = False

    def send(self, request):
        raise SafeError('Live commands disabled; no proxy connection attempted')


class MockProxy:
    """Internal test transport, not injectable through a tool or environment setting."""
    simulated = True

    def __init__(self, response=None):
        self.calls = 0
        self.response = response if response is not None else {'response': {'result': True}}

    def send(self, request):
        self.calls += 1
        return self.response


class CommandAdapter:
    """REST client for the official signing proxy, not an implementation of signing.

    Default transport refuses network access. The injected transport interface is
    for tests; approval is always consumed BEFORE any attempt and never restored.
    """
    def __init__(self, ledger, transport=None, budget=None):
        self.budget = budget
        self.ledger = ledger
        self.transport = transport if transport is not None else DisabledNetwork()

    def submit(self, intent, approval, access_token):
        valid = intent.validated()
        if not isinstance(access_token, str) or not access_token or len(access_token) > 16000 or any(c.isspace() for c in access_token):
            raise SafeError('Invalid command token')
        self.ledger.consume(approval, valid)
        if self.budget is not None:
            self.budget.reserve('commands')
        elif not isinstance(self.transport, DisabledNetwork) and self.transport.simulated is not True:
            raise SafeError('Durable budget required for a live transport')
        request = urllib.request.Request(
            f'https://localhost:4443/api/1/vehicles/{valid.target}/command/{valid.command}',
            data=valid.payload_json, method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json', 'Accept': 'application/json'})
        try:
            response = self.transport.send(request)
        except SafeError:
            if isinstance(self.transport, DisabledNetwork):
                raise SafeError('Live commands disabled; no proxy connection attempted') from None
            raise SafeError('Command rejected; approval consumed; details withheld') from None
        except Exception:
            raise SafeError('Command outcome unknown; approval consumed; no automatic retry') from None
        # Do not reflect arbitrary reason/error strings or claim physical execution.
        if not isinstance(response, dict) or not isinstance(response.get('response'), dict):
            raise SafeError('Unexpected proxy response; approval consumed')
        accepted = response['response'].get('result')
        if type(accepted) is not bool:
            raise SafeError('Unexpected proxy response; approval consumed')
        return {'command': valid.command, 'accepted': accepted,
                'simulated': self.transport.simulated, 'vehicle_execution_verified': False,
                'approval_consumed': True}
