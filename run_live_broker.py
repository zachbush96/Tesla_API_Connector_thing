#!/usr/bin/env python3
"""Tesla read broker; live controls require separate protected activation policy."""
import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import sys
import urllib.request
import webbrowser
from tesla_connector.broker import Broker
from tesla_connector.listener import serve_broker
from tesla_connector.oidc import TeslaOIDCVerifier
from tesla_connector.oauth_transport import TLSOAuthTransport
from tesla_connector.runtime import compose_local_runtime
from tesla_connector.service import SafeError, private_file, NoRedirect
from tesla_connector.storage import PrivateStore
from tesla_connector.audit import SetupAudit,runtime_metadata
from tesla_connector.setup_loop import WaitingIdentityVerifier, SetupReporter


def diagnostic_category(error, stage):
    # Emit only constant categories, never exception text or user input.
    from tesla_connector.oidc import IdentityValidationError
    if isinstance(error, IdentityValidationError):
        return 'identity-validation/' + error.code + ': authorization was not stored; report this category only'
    message = str(error) if isinstance(error, SafeError) else ''
    if message.startswith('Invalid OAuth callback') or message == 'OAuth issuer mismatch':
        return 'callback-format: copy the complete Tesla callback privately; issuer must match Tesla'
    if message == 'OAuth state expired, consumed or mismatched':
        return 'callback-state: restart setup and use that same fresh session within five minutes'
    if message == 'Owner denied authorization or callback incomplete':
        return 'consent-denied: authorize Vehicle Information in Tesla'
    if message.startswith('OAuth exchange'):
        return 'token-exchange: Tesla request failed; authorization was not stored'
    if message.startswith('OIDC') or message.startswith('Verified OIDC'):
        return 'identity-validation: signed identity validation failed; authorization was not stored'
    if message == 'Protected token persistence failed':
        return 'keychain-storage: token persistence failed; authorization is not confirmed'
    return stage + ': operation failed; private input and upstream details withheld'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup', action='store_true', help='Owner-only fresh consent; stores tokens in Keychain')
    parser.add_argument('--setup-offline', action='store_true', help='Owner-only read consent plus offline_access; stores rotating refresh token in Keychain')
    parser.add_argument('--setup-controls', action='store_true', help='Owner-only explicit command/charging consent; never enables execution')
    parser.add_argument('--setup-location', action='store_true', help='Add precise-source location to explicit command setup consent')
    parser.add_argument('--setup-loop', action='store_true', help='One consent/code exchange; retry only public key validation for up to ten minutes')
    parser.add_argument('--monthly-read-budget-microdollars', type=int, help='Explicit account-reviewed allowance; default zero')
    parser.add_argument('--diagnose-local',action='store_true',help='Write source/dependency audit without credential access, consent or car calls')
    parser.add_argument('--state-dir', required=True, type=Path, help='New owner-private absolute state directory')
    parser.add_argument('--secrets-dir', required=True, type=Path, help='New owner-private absolute secrets directory')
    parser.add_argument('--region', choices=('na','eu','cn'), default='na')
    args = parser.parse_args()
    if not args.state_dir.is_absolute() or not args.secrets_dir.is_absolute():
        parser.error('Use explicit absolute private directories')
    if args.setup_location and not args.setup_controls:
        parser.error('--setup-location requires --setup-controls')
    args.setup = args.setup or args.setup_loop or args.setup_offline or args.setup_controls
    base = Path(__file__).resolve().parent
    state = args.state_dir
    state.mkdir(mode=0o700, exist_ok=True)
    PrivateStore(state)  # Validates owner-only directory; creates securely if absent.
    audit=SetupAudit(state/'setup-audit.jsonl')
    audit('runtime',runtime_metadata(base))
    print('Setup correlation ID: '+audit.correlation_id)
    if args.diagnose_local:
        print('Local source/dependency audit saved. No credential, consent or vehicle request.')
        return
    config_path = state / 'vehicle.json'
    if args.setup:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise SafeError('Owner setup requires a private interactive Terminal')
        target = json.loads(private_file(config_path))['target'] if config_path.exists() else getpass.getpass('Vehicle VIN (hidden): ').strip().upper()
    else:
        config = json.loads(private_file(config_path))
        target = config['target']
    verifier = TeslaOIDCVerifier(audit=audit)
    reporter = SetupReporter(state / 'setup-report.json', verifier=verifier)
    if args.setup_loop:
        verifier = WaitingIdentityVerifier(verifier, event=reporter)
    runtime = compose_local_runtime(state, 'configured-owner', target,
        region=args.region, oauth_transport=TLSOAuthTransport(approved=True,audit=audit), oidc_verifier=verifier,audit=audit,
        read_opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()))
    if args.setup:
        session = secrets.token_urlsafe(32)
        scopes = ('openid', 'vehicle_device_data', 'offline_access') if args.setup_offline else ('openid', 'vehicle_device_data')
        if args.setup_controls:
            scopes = ('openid', 'offline_access', 'vehicle_device_data', 'vehicle_cmds', 'vehicle_charging_cmds')
            if args.setup_location: scopes += ('vehicle_location',)
        url = runtime.oauth.begin(session, scopes)
        if not webbrowser.open(url):
            raise SafeError('Private owner browser unavailable; restart setup')
        print(('Approve Tesla command/charging consent' if args.setup_controls else 'Approve Tesla read consent') + (', including precise-source location' if args.setup_location else '') + '. Copy the complete callback URL privately even if the page is unavailable.')
        callback = getpass.getpass('Callback URL (hidden): ')
        try:
            runtime.oauth.callback(callback, session)
        except Exception as error:
            from tesla_connector.oidc import IdentityValidationError
            if isinstance(error, IdentityValidationError):
                reporter(error.code, 1)
            audit('setup-result',{'vehicle_read_performed':False,'stored':False})
            raise SystemExit('Owner setup failed at ' + diagnostic_category(error, 'consent-validation')) from None
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) if not config_path.exists() else None
        if fd is None:
            private_file(config_path)  # Refuse unsafe existing configuration before replacing.
            temporary = state / ('vehicle-' + secrets.token_hex(12))
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        else:
            temporary = config_path
        with os.fdopen(fd, 'w') as output:
            json.dump({'target': target}, output); output.flush(); os.fsync(output.fileno())
        if temporary != config_path:
            os.replace(temporary, config_path)
        reporter('keychain-saved', 0)
        print('Authorization saved in local Keychain. No vehicle read or command performed; execution remains disabled.')
        return
    # Keep the protected non-car endpoint available when fresh consent is needed.
    # Read authorization remains enforced by the service before every car call.
    from tesla_connector.renewal import Renewal
    renewal = Renewal(runtime.oauth)
    renewal.start()
    if args.monthly_read_budget_microdollars is not None:
        runtime.budget.configure(args.monthly_read_budget_microdollars)
    protected = args.secrets_dir
    remote_operations=None
    signer_config=state/'signer-service.json'
    if signer_config.exists():
        private_file(signer_config)
        from tesla_connector.remote_controls import RemoteOperations,SignerMockExecutor
        remote_operations=RemoteOperations('configured-owner',target,executor=SignerMockExecutor(protected/'signer-tls.crt',private_file(protected/'mcp.token')))
    # Optional reviewed local policy; no default activation, allowance change,
    # vehicle diagnostic, signer startup or physical operation during composition.
    from tesla_connector.live_activation import compose_configured_controls
    controls=compose_configured_controls(runtime,'configured-owner',target,state,protected)
    if controls is not None and controls.executor.execution_enabled:
        remote_operations=controls.operations
    broker = Broker('configured-owner', private_file(protected / 'operator.token'),
        private_file(protected / 'mcp.token'), gateway_token=private_file(protected / 'gateway.token'),
        service=runtime.service, allow_live_reads=True,remote_operations=remote_operations,
        signer_bridge=controls.bridge if controls is not None else None,
        signer_bridge_token=controls.bridge_token if controls is not None else None)
    serve_broker(broker)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as error:
        raise SystemExit('Live broker unavailable at ' + diagnostic_category(error, 'local-configuration-or-startup')) from None
