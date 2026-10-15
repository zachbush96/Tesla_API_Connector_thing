"""Stateless /mcp boundary model. No network server, Site or raw-header trust.

A hosting integration must supply identity ONLY from its verified middleware.
This module intentionally accepts no raw authenticated-user headers.
"""
import json
from dataclasses import dataclass
from .mcp import PROTOCOLS, TOOLS
from .service import Config, SafeError, Service


@dataclass(frozen=True, repr=False)
class VerifiedIdentity:
    user_id: str


class MockHTTPMCP:
    def __init__(self, owner_id, *, service=None, allow_live_reads=False):
        if not isinstance(owner_id, str) or not owner_id:
            raise SafeError('Configured owner identity required')
        self.owner_id = owner_id
        if service is not None and (not isinstance(service, Service) or service.config.mode == 'live-read' and allow_live_reads is not True):
            raise SafeError('Explicit operator live-read opt-in required')
        self.service = service or Service(Config())  # Default stays mock; no transport activation.

    def post(self, path, raw, identity=None):
        # Identity is an adapter input supplied by trusted hosting, never JSON body.
        if path != '/mcp':
            return 404, {}
        if type(identity) is not VerifiedIdentity or not identity.user_id:
            return 401, {}
        if identity.user_id != self.owner_id:
            return 403, {}
        if not isinstance(raw, bytes) or len(raw) > 65536:
            return 413, {}
        try:
            message = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            return 400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0' or not isinstance(message.get('method'), str):
            return 400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}
        ident = message.get('id')
        params = message.get('params', {})
        if not isinstance(params, dict) or ('id' in message and type(ident) not in (str, int)):
            return 400, {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32602, 'message': 'Invalid parameters'}}
        if 'id' not in message:
            return 202, None
        method = message['method']
        if method == 'initialize':
            version = params.get('protocolVersion')
            result = {'protocolVersion': version if version in PROTOCOLS else PROTOCOLS[0],
                      'capabilities': {'tools': {}}, 'serverInfo': {'name': 'tesla-connector-http-' + self.service.config.mode, 'version': '0.2.0'}}
        elif method == 'ping':
            result = {}
        elif method == 'tools/list':
            result = {'tools': TOOLS}
        elif method == 'tools/call':
            try:
                if set(params) - {'name', 'arguments', '_meta'} or params.get('name') not in {t['name'] for t in TOOLS}:
                    raise SafeError('Unknown tool or invalid parameters')
                output = self.service.call(params['name'], params.get('arguments', {}))
                result = {'content': [{'type': 'text', 'text': json.dumps(output, allow_nan=False)}], 'isError': False}
            except SafeError as error:
                result = {'content': [{'type': 'text', 'text': str(error)}], 'isError': True}
            except Exception:
                result = {'content': [{'type': 'text', 'text': 'Tool failed; details withheld'}], 'isError': True}
        else:
            return 200, {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32601, 'message': 'Method not found'}}
        return 200, {'jsonrpc': '2.0', 'id': ident, 'result': result}
