"""Explicit owner-local composition; absent/disabled policy preserves mock controls.

This module neither configures allowance nor starts a signer, listener or request.
No request/model field selects a path, target, credential, key or activation mode.
"""
import hashlib
import json
from pathlib import Path
from .audit import strict_object
from .service import SafeError, private_file


POLICY_FIELDS = {'version', 'execution_enabled', 'pairing_diagnostic_enabled'}
OPTIONAL_POLICY_FIELDS = {'infotainment_diagnostic_enabled','remote_owner_approval_enabled'}
SIGNER_FIELDS = {'owner', 'target', 'token_file', 'signing_private_file',
                 'signing_public_file', 'tls_certificate_file', 'tls_private_file'}


def activation_policy(path):
    try:
        data = json.loads(private_file(path), object_pairs_hook=strict_object)
        if (not isinstance(data, dict) or not POLICY_FIELDS <= set(data) <= POLICY_FIELDS | OPTIONAL_POLICY_FIELDS
                or type(data['version']) is not int or data['version'] != 1
                or any(type(data[k]) is not bool for k in set(data) - {'version'})):
            raise ValueError()
        if data.get('infotainment_diagnostic_enabled',False) and (data['execution_enabled'] or data['pairing_diagnostic_enabled']):
            raise ValueError()
        if data.get('remote_owner_approval_enabled',False) and (not data['execution_enabled'] or data['pairing_diagnostic_enabled'] or data.get('infotainment_diagnostic_enabled',False)):raise ValueError()
        return {**data,'infotainment_diagnostic_enabled':data.get('infotainment_diagnostic_enabled',False),'remote_owner_approval_enabled':data.get('remote_owner_approval_enabled',False)}
    except Exception:
        raise SafeError('Protected control activation policy refused') from None


def public_signing_key_digest(path):
    """Digest existing public key in the SDK's SEC1 format; no private-key read."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        raw = private_file(path).encode('ascii')
        if b'PRIVATE KEY' in raw:
            raise ValueError()
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError()
        public = key.public_bytes(serialization.Encoding.X962,
                                  serialization.PublicFormat.UncompressedPoint)
        return hashlib.sha256(public).hexdigest()
    except Exception:
        raise SafeError('Existing public signing key refused') from None


def compose_configured_controls(runtime, owner, target, state, protected):
    """Load the separate protected policy only during explicitly reviewed startup."""
    state, protected = Path(state), Path(protected)
    policy_path = state / 'control-service.json'
    if not policy_path.exists():
        return None
    policy = activation_policy(policy_path)
    if not any(policy[k] for k in ('execution_enabled','pairing_diagnostic_enabled','infotainment_diagnostic_enabled')):
        return None
    try:
        signer = json.loads(private_file(state / 'signer-service.json'), object_pairs_hook=strict_object)
        if (not isinstance(signer, dict) or set(signer) != SIGNER_FIELDS
                or signer['owner'] != owner or signer['target'] != target
                or signer['token_file'] != str(protected / 'mcp.token')
                or any(not isinstance(signer[k], str) or not Path(signer[k]).is_absolute()
                       for k in SIGNER_FIELDS - {'owner', 'target'})):
            raise ValueError()
        # The reviewed restricted signer pins the North America Fleet origin.
        # Do not send another region's bearer or target to that fixed origin.
        if runtime.service.config.region != 'na':
            raise ValueError()
        status = runtime.budget.total_status()
        if (status.get('configured') is not True
                or type(status.get('cap_microdollars')) is not int
                or not 0 < status['cap_microdollars'] <= 100000):
            raise ValueError()
        key_digest = public_signing_key_digest(signer['signing_public_file'])
        token = private_file(protected / 'mcp.token')
        from .live_controls import compose_live_controls, FleetCapabilityReader
        controls=compose_live_controls(runtime, owner, target,
            certificate_path=signer['tls_certificate_file'], signer_token=token,
            signing_key_sha256=key_digest,
            execution_enabled=policy['execution_enabled'],
            pairing_diagnostic_enabled=policy['pairing_diagnostic_enabled'],
            infotainment_diagnostic_enabled=policy['infotainment_diagnostic_enabled'],
            capability_opener=FleetCapabilityReader.approved_opener())
        controls.operations.remote_owner_approval_enabled=policy["remote_owner_approval_enabled"]
        return controls
    except Exception:
        raise SafeError('Protected live control composition refused; execution unavailable') from None
