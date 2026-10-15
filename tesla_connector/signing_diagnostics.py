"""Bounded enum-only signing evidence. Never inspect exception messages or bodies."""
import ssl
import socket
import http.client
import urllib.error

from .service import SafeError

STAGES = frozenset(('operation_started', 'reservation_attempted', 'reservation_acknowledged',
    'http_initiated', 'request_written', 'response_received', 'response_validated',
    'authenticated_session_ready', 'operation_succeeded', 'operation_failed'))
KINDS = frozenset(('operation', 'handshake', 'command', 'state_handshake', 'state_query', 'navigation'))
PYTHON_EXCEPTIONS = frozenset(('python_http_error', 'python_url_error', 'python_timeout',
    'python_ssl_error', 'python_validation', 'python_other', 'python_tls_certificate',
    'python_connection_refused', 'python_connection_reset', 'python_dns_error',
    'python_incomplete_read', 'python_response_too_large', 'python_json_invalid',
    'python_content_type', 'python_http_status', 'python_journal_error'))
EXCEPTIONS = frozenset(('none', 'local_refused', 'bridge_refused', 'context_deadline',
    'context_canceled', 'tls_certificate', 'tls_handshake', 'network_error',
    'response_read_error', 'http_status', 'json_invalid', 'vehicle_rejected',
    'sdk_authentication', 'sdk_error', 'response_too_large','response_content_type',
    'fleet_envelope_invalid_json','fleet_envelope_invalid_shape','fleet_envelope_invalid_base64',
    'fleet_envelope_too_large','fleet_envelope_error','fleet_response_missing',
    'routable_invalid_protobuf','routable_unknown_fields','routable_uuid_missing',
    'routable_uuid_length','routable_uuid_mismatch','routable_source_missing','routable_source_type',
    'routable_domain_mismatch','routable_destination_missing','routable_destination_type',
    'routable_destination_length','routable_destination_mismatch','routable_status_wait',
    'routable_status_error','routable_status_unknown','session_info_missing',
    'session_info_invalid_protobuf','session_info_unknown_fields','session_info_status_unknown',
    'session_info_tag_missing','session_info_tag_length','session_info_invalid_public_key',
    'session_info_exchange_failed','session_info_hmac_failed','session_info_hmac_mismatch',
    'session_info_late','guard_handshake_retry_blocked','command_cache_missing',
    'command_cache_invalid','command_exchange_failed','command_metadata_invalid',
    'command_nonce_length','command_tag_length','command_decryption_failed','command_payload_missing',
    'command_payload_invalid','command_status_missing','command_status_rejected','command_status_reason',
    'command_status_unknown_fields','command_ack_missing','sdk_key_not_paired',
    'sdk_invalid_public_key','sdk_bad_response','sdk_no_session','sdk_not_connected','sdk_requires_key',
    'sdk_protocol_unsupported','sdk_replayed_response','sdk_unexpected_public_key',
    'sdk_no_decryption_context','sdk_requires_encryption','sdk_requires_ble','sdk_busy','sdk_unknown',
    'sdk_routable_fault','sdk_nominal_error','network_timeout','network_dns','network_refused',
    'network_reset')) | PYTHON_EXCEPTIONS
CATEGORIES = frozenset(('none', 'local', 'bridge', 'context', 'tls', 'transport',
    'http', 'response', 'vehicle', 'sdk','fleet','routable','authentication'))
VEHICLE_ERRORS = frozenset(('none', 'unclassified', 'rejected', 'invalid_key',
    'invalid_signature', 'invalid_session', 'request_expired', 'not_whitelisted',
    'busy', 'malformed_response','timeout','unknown_key','inactive_key','invalid_key_handle',
    'invalid_counter','incorrect_epoch','repeated_counter','insufficient_privileges',
    'invalid_domain','invalid_command','decoding','internal','wrong_personalization',
    'bad_parameter','keychain_full','invalid_iv','identity_missing','metadata_hash',
    'expiry_too_long','remote_access_disabled','remote_service_access_disabled',
    'account_credentials_required','request_mtu','response_mtu','response_encryption_required',
    'unknown_fault'))
LEGACY_FLAGS = frozenset(('reservation_acknowledged', 'http_initiated', 'request_written',
    'response_received', 'authenticated_session_ready'))
FLAGS = LEGACY_FLAGS | {'checkpoint_persistence_failed','local_finalization_failed'}
FIELDS = frozenset(('stage', 'failure_stage', 'kind', 'exception_type', 'category',
    'http_status', 'vehicle_error')) | FLAGS
LEGACY_FIELDS = FIELDS - {'checkpoint_persistence_failed','local_finalization_failed'}
UPSTREAM_ERROR = 'Local signing operation refused or uncertain; no automatic retry'
FAILURE = 'Local signing outcome unconfirmed; operation consumed; no wake or retry'


def valid_status(value):
    return type(value) is int and (value == 0 or 100 <= value <= 599)


def checked_diagnostic(value):
    if type(value)is dict and set(value)==LEGACY_FIELDS:
        value={**value,'checkpoint_persistence_failed':False,'local_finalization_failed':False}
    if (type(value) is not dict or set(value) != FIELDS
            or any(type(value[k]) is not str for k in
                   ('stage','failure_stage','kind','exception_type','category','vehicle_error'))
            or value['stage'] not in STAGES or value['failure_stage'] not in STAGES | {'none'}
            or value['kind'] not in KINDS or value['exception_type'] not in EXCEPTIONS
            or value['category'] not in CATEGORIES or value['vehicle_error'] not in VEHICLE_ERRORS
            or not valid_status(value['http_status'])
            or any(type(value[k]) is not bool for k in FLAGS)):
        raise SafeError('Sanitized signing diagnostic refused')
    # A write proves HTTP initiation, never car acceptance or physical effect.
    if (value['request_written'] and not value['http_initiated']
            or value['response_received'] and not value['http_initiated']
            or value['http_initiated'] and not value['reservation_acknowledged']
            or (value['exception_type']=='none') != (value['category']=='none')
            or (value['exception_type']=='none') != (value['failure_stage']=='none')
            or value['vehicle_error']!='none' and value['exception_type']=='none'
            or value['kind'] in {'handshake','state_handshake'}
               and value['authenticated_session_ready'] and not value['response_received']):
        raise SafeError('Sanitized signing diagnostic refused')
    return dict(value)


def local_transport(error, stage, status=0):
    """Class membership only; arbitrary class names/repr/args are never emitted."""
    # urllib wraps useful socket/TLS failures in URLError.reason. Inspect one
    # exception object's class only, never string reasons or nested messages.
    underlying=error.reason if isinstance(error,urllib.error.URLError) and not isinstance(error,urllib.error.HTTPError) else error
    if isinstance(error,TransportEvidenceError):kind=error.code
    elif isinstance(error,urllib.error.HTTPError):kind='python_http_error'
    elif isinstance(underlying,ssl.SSLCertVerificationError):kind='python_tls_certificate'
    elif isinstance(underlying,ssl.SSLError):kind='python_ssl_error'
    elif isinstance(underlying,TimeoutError):kind='python_timeout'
    elif isinstance(underlying,socket.gaierror):kind='python_dns_error'
    elif isinstance(underlying,ConnectionRefusedError):kind='python_connection_refused'
    elif isinstance(underlying,ConnectionResetError):kind='python_connection_reset'
    elif isinstance(underlying,http.client.IncompleteRead):kind='python_incomplete_read'
    elif isinstance(error,urllib.error.URLError):kind='python_url_error'
    elif isinstance(error,(ValueError,SafeError,TypeError)):kind='python_validation'
    else:kind='python_other'
    return {'stage':stage if type(stage)is str and stage in STAGES else 'operation_failed',
            'exception_type':kind, 'http_status':status if valid_status(status) else 0}


class TransportEvidenceError(SafeError):
    """An internal fixed classification, with no reflected input or body."""
    def __init__(self,code):
        if code not in {'python_response_too_large','python_json_invalid',
                        'python_content_type','python_http_status'}:
            raise SafeError('Sanitized transport classification refused')
        super().__init__('Local signing response validation failed; private details withheld')
        self.code=code


def checked_local_transport(value):
    if (type(value) is not dict or set(value) != {'stage','exception_type','http_status'}
            or type(value['stage']) is not str or type(value['exception_type']) is not str
            or value['stage'] not in STAGES or value['exception_type'] not in PYTHON_EXCEPTIONS
            or not valid_status(value['http_status'])):
        raise SafeError('Sanitized local transport diagnostic refused')
    return dict(value)


class SanitizedSigningError(SafeError):
    def __init__(self, diagnostic=None, transport=None):
        super().__init__(FAILURE)
        self.diagnostic = checked_diagnostic(diagnostic) if diagnostic is not None else None
        self.local_transport = checked_local_transport(transport) if transport is not None else None

    def finalization_failed(self):
        if self.diagnostic is None:
            self.diagnostic={'stage':'operation_failed','failure_stage':'operation_failed','kind':'operation',
                'exception_type':'python_journal_error','category':'local','http_status':0,
                'vehicle_error':'none',**{flag:False for flag in FLAGS}}
        self.diagnostic=checked_diagnostic({**self.diagnostic,'local_finalization_failed':True})
        return self

    def public_fields(self):
        result = {'error_category':'upstream_tool'}
        if self.diagnostic is not None: result['diagnostic'] = checked_diagnostic(self.diagnostic)
        if self.local_transport is not None: result['local_transport'] = checked_local_transport(self.local_transport)
        return result
