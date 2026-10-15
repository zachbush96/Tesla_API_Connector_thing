"""Explicit read/command boundary; no live command execution in this prototype."""
import json
import math
import os
import re
import stat
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


class SafeError(Exception):
    """Only fixed, non-sensitive messages may cross the tool boundary."""


def private_file(path):
    """Open without following final symlinks; require current-user ownership and 0600."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise SafeError('Secret file must be owner-only and owned by this user')
            value = stream.read(16385)
            if len(value) > 16384:
                raise SafeError('Secret file too large')
            return value.strip()
    except (OSError, UnicodeError):
        raise SafeError('Cannot read protected secret file') from None


@dataclass(repr=False)
class Config:
    mode: str = 'mock'
    allow_live_reads: bool = False
    region: str = 'na'
    vin_file: str = field(default='', repr=False)
    token_file: str = field(default='', repr=False)

    def __post_init__(self):
        if self.mode not in ('mock', 'live-read') or self.region not in ('na', 'eu', 'cn'):
            raise SafeError('Invalid configuration')
        if self.mode == 'live-read' and not self.allow_live_reads:
            raise SafeError('Live reads require explicit operator opt-in')

    @classmethod
    def environment(cls):
        return cls(os.getenv('TESLA_CONNECTOR_MODE', 'mock'),
                   os.getenv('TESLA_CONNECTOR_ALLOW_LIVE_READS') == 'true',
                   os.getenv('TESLA_CONNECTOR_REGION', 'na'),
                   os.getenv('TESLA_CONNECTOR_VIN_FILE', ''),
                   os.getenv('TESLA_CONNECTOR_TOKEN_FILE', ''))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeError('Upstream redirect refused')


class FleetReader:
    """Fixed official regional origins; GET only, TLS verification, no retries/wakes."""
    def __init__(self, config, credential_provider=None, budget=None):
        if config.mode != 'live-read' or config.allow_live_reads is not True:
            raise SafeError('Fleet reader requires explicit live configuration')
        self.config = config
        self.credential_provider = credential_provider
        self.budget = budget
        self.attempts = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def data(self, endpoint):
        if endpoint not in ('charge_state', 'location_data', 'climate_state'):
            raise SafeError('Read endpoint not allowed')
        if self.attempts >= 30:
            raise SafeError('Live-read session budget exhausted; operator review required')
        if self.credential_provider is None:
            vin = private_file(self.config.vin_file)
            token = private_file(self.config.token_file)
        else:
            vin, token = self.credential_provider(endpoint)
        if not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}', vin):
            raise SafeError('Invalid vehicle configuration')
        if not token or len(token) > 16000 or any(c.isspace() for c in token):
            raise SafeError('Invalid token configuration')
        suffix = 'cn' if self.config.region == 'cn' else 'com'
        origin = f'https://fleet-api.prd.{self.config.region}.vn.cloud.tesla.{suffix}'
        request = urllib.request.Request(
            f'{origin}/api/1/vehicles/{vin}/vehicle_data?endpoints={endpoint}',
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'})
        if self.budget is not None:
            self.budget.reserve('data')
        try:
            self.attempts += 1
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise SafeError('Upstream response too large')
                body = json.loads(raw)
            if not isinstance(body, dict) or not isinstance(body.get('response'), dict):
                raise SafeError('Unexpected upstream response')
            return body['response']
        except urllib.error.HTTPError as error:
            # Never expose URL, upstream body, token, VIN, location or exception repr.
            error.close()
            if error.code == 401:
                raise SafeError('Tesla authorization expired or rejected') from None
            if error.code == 403:
                raise SafeError('Tesla permission denied') from None
            if error.code == 429:
                raise SafeError('Tesla rate limit reached; do not retry automatically') from None
            raise SafeError('Tesla unavailable; vehicle may be asleep; no wake attempted') from None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError, SafeError):
            raise SafeError('Tesla read failed; no automatic retry') from None


class MockReader:
    def data(self, endpoint):
        if endpoint == 'climate_state':
            return {'climate_state': {'inside_temp': 19.0, 'timestamp': 1700000000000}}
        if endpoint == 'charge_state':
            return {'charge_state': {'battery_level': 72, 'charging_state': 'Disconnected',
                    'charge_limit_soc': 80, 'charger_power': 0}}
        # Synthetic location deliberately chosen to be unrelated to the user.
        return {'location_data': {'latitude': 0.0, 'longitude': 0.0}}


def number(value, low, high):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and low <= value <= high
    except OverflowError:
        valid = False
    if not valid:
        raise SafeError('Numeric input outside permitted range')
    return value


def arguments(args, required):
    if not isinstance(args, dict) or set(args) != set(required):
        raise SafeError('Arguments must match the tool schema exactly')


def navigation_payload(destination, timestamp_ms=None):
    if not isinstance(destination, str) or not 1 <= len(destination) <= 300 or not destination.strip() or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in destination):
        raise SafeError('Destination must be nonempty plain text, at most 300 characters')
    # Use the exact share format from Tesla's expanded official Request example.
    if timestamp_ms is None:
        timestamp_ms = str(int(time.time() * 1000))
    if not isinstance(timestamp_ms, str) or not re.fullmatch(r'[0-9]{13}', timestamp_ms):
        raise SafeError('Invalid navigation timestamp')
    return {'type': 'share_ext_content_raw',
            'value': {'android.intent.ACTION': 'android.intent.action.SEND',
                      'android.intent.TYPE': 'text/plain',
                      'android.intent.TEXT': destination,
                      'android.intent.extra.TEXT': destination},
            'locale': 'en-US', 'timestamp_ms': timestamp_ms}


def command_plan(name, args):
    """Build Tesla proxy payloads internally; caller receives only a redacted preview."""
    if name == 'preview_navigation':
        arguments(args, ('destination',))
        return 'navigation_request', navigation_payload(args['destination'])
    if name == 'preview_temperature':
        arguments(args, ('celsius',))
        temperature = number(args['celsius'], 15, 28)
        return 'set_temps', {'driver_temp': temperature, 'passenger_temp': temperature}
    raise SafeError('Unknown command')


class Service:
    def __init__(self, config=None, reader=None):
        self.config = config or Config.environment()
        if self.config.mode == 'live-read' and isinstance(reader, MockReader) or self.config.mode == 'mock' and isinstance(reader, FleetReader):
            raise SafeError('Reader mode mismatch')
        self.reader = reader or (MockReader() if self.config.mode == 'mock' else FleetReader(self.config))

    def call(self, name, args):
        if name in ('read_battery_charging', 'read_location', 'read_temperature'):
            arguments(args, ())
            if name == 'read_temperature':
                state = self.reader.data('climate_state').get('climate_state', {})
                if not isinstance(state, dict):
                    raise SafeError('Unexpected upstream data')
                value = number(state.get('inside_temp'), -60, 100)
                stamp = state.get('timestamp')
                if type(stamp) is not int or not 0 <= stamp <= 9999999999999:
                    raise SafeError('Invalid vehicle temperature timestamp')
                return {'mode': self.config.mode, 'inside_celsius': value,
                        'inside_fahrenheit': round(value * 9 / 5 + 32, 1),
                        'vehicle_timestamp_ms': stamp, 'synthetic': self.config.mode == 'mock'}
            if name == 'read_battery_charging':
                state = self.reader.data('charge_state').get('charge_state', {})
                if not isinstance(state, dict):
                    raise SafeError('Unexpected upstream data')
                charging = state.get('charging_state')
                if charging not in ('Charging', 'Disconnected', 'Complete', 'Stopped', 'Starting', 'NoPower'):
                    charging = 'Unknown'
                return {'mode': self.config.mode, 'battery_percent': number(state.get('battery_level'), 0, 100),
                        'charging_state': charging, 'charge_limit_percent': number(state.get('charge_limit_soc'), 0, 100),
                        'charger_power_kw': number(state.get('charger_power'), 0, 1000),
                        'freshness': 'on-demand response; no caching; vehicle timestamp not verified'}
            data = self.reader.data('location_data')
            state = data.get('location_data', data.get('drive_state', {}))
            if not isinstance(state, dict):
                raise SafeError('Unexpected upstream data')
            # Only coarse coordinates leave this process (about 11 km latitude resolution).
            return {'mode': self.config.mode, 'latitude_approx': round(number(state.get('latitude'), -90, 90), 1),
                    'longitude_approx': round(number(state.get('longitude'), -180, 180), 1),
                    'precision': '0.1 degree; sensitive, do not persist', 'synthetic': self.config.mode == 'mock'}
        command, payload = command_plan(name, args)
        result = {'dry_run': True, 'executed': False, 'command': command,
                  'transport': 'Tesla official Vehicle Command Proxy (not connected)',
                  'live_commands': 'blocked in this prototype'}
        if command == 'set_temps':
            result['celsius'] = payload['driver_temp']
        else:
            result['destination'] = '[redacted]'
        return result
