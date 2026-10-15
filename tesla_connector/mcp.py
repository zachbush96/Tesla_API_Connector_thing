"""Minimal MCP stdio server. No listening socket, credentials or persistent grants."""
import json
import sys
from .service import SafeError, Service

PROTOCOLS = ('2025-11-25', '2025-06-18', '2024-11-05')


def tool(name, description, properties, read):
    return {'name': name, 'description': description,
            'inputSchema': {'type': 'object', 'properties': properties,
                            'required': list(properties), 'additionalProperties': False},
            'annotations': {'readOnlyHint': read, 'destructiveHint': False,
                            'idempotentHint': True, 'openWorldHint': read}}


TOOLS = [
    tool('read_battery_charging', 'READ: on-demand battery and charging. Mock by default; live reads can be billed.', {}, True),
    tool('read_temperature', 'READ: cabin temperature and vehicle timestamp only; synthetic in mock mode. No HVAC change or wake.', {}, True),
    tool('read_location', 'READ: coarse location only; synthetic in mock mode. Never persist tool results.', {}, True),
    tool('preview_navigation', 'COMMAND PREVIEW ONLY: validate an address/place; redact destination; never send a live command.',
         {'destination': {'type': 'string', 'minLength': 1, 'maxLength': 300}}, False),
    tool('preview_temperature', 'COMMAND PREVIEW ONLY: both zones, Celsius. Does not start HVAC or execute.',
         {'celsius': {'type': 'number', 'minimum': 15, 'maximum': 28}}, False),
]


class Session:
    def __init__(self, service=None):
        self.service = service or Service()
        self.initialized = False
        self.ready = False

    def handle(self, request):
        ident = request.get('id') if isinstance(request, dict) else None
        def error(code, message):
            return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': code, 'message': message}}
        if not isinstance(request, dict) or request.get('jsonrpc') != '2.0' or not isinstance(request.get('method'), str):
            return error(-32600, 'Invalid request')
        if 'id' in request and (type(ident) not in (int, str) or isinstance(ident, bool)):
            return error(-32600, 'Invalid request id')
        method = request['method']
        params = request.get('params', {})
        if not isinstance(params, dict):
            return error(-32602, 'Invalid parameters')
        if 'id' not in request:
            if method == 'notifications/initialized' and self.initialized:
                self.ready = True
            return None
        if method == 'initialize':
            if self.initialized or not isinstance(params.get('protocolVersion'), str):
                return error(-32602, 'Invalid initialization')
            self.initialized = True
            version = params['protocolVersion']
            result = {'protocolVersion': version if version in PROTOCOLS else PROTOCOLS[0],
                      'capabilities': {'tools': {}},
                      'serverInfo': {'name': 'tesla-connector-fleet', 'version': '0.3.0'}}
        elif method == 'ping':
            result = {}
        elif not self.ready:
            return error(-32000, 'Initialize session before calling tools')
        elif method == 'tools/list':
            result = {'tools': TOOLS}
        elif method == 'tools/call':
            try:
                if set(params) - {'name', 'arguments', '_meta'} or params.get('name') not in {t['name'] for t in TOOLS}:
                    raise SafeError('Unknown tool or invalid parameters')
                output = self.service.call(params['name'], params.get('arguments', {}))
                result = {'content': [{'type': 'text', 'text': json.dumps(output, allow_nan=False)}], 'isError': False}
            except SafeError as exception:
                result = {'content': [{'type': 'text', 'text': str(exception)}], 'isError': True}
            except Exception:
                result = {'content': [{'type': 'text', 'text': 'Tool failed; details withheld'}], 'isError': True}
        else:
            return error(-32601, 'Method not found')
        return {'jsonrpc': '2.0', 'id': ident, 'result': result}


def main():
    try:
        session = Session()
    except Exception:
        print('Configuration rejected; details withheld', file=sys.stderr)
        return 1
    while True:
        line = sys.stdin.buffer.readline(65537)
        if not line:
            break
        if len(line) > 65536:
            print('Oversized message refused', file=sys.stderr)
            return 1
        try:
            request = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            response = session.handle(request)
        except (ValueError, UnicodeError, RecursionError):
            response = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
        if response is not None:
            print(json.dumps(response, allow_nan=False), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
