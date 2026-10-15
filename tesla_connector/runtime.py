"""Local production composition; constructed explicitly, never used by mock launcher."""
from dataclasses import dataclass, field
import re
from .keychain import MacKeychain, KeychainTokenVault, credentials
from .oauth import OAuthClient
from .service import Config, FleetReader, SafeError, Service
from .storage import PrivateStore, DurableBudget


@dataclass(repr=False)
class LocalRuntime:
    oauth: object = field(repr=False)
    service: object = field(repr=False)
    budget: object = field(repr=False)


def compose_local_runtime(state_directory,owner,target,*,backend=None,oauth_transport=None,
                          oidc_verifier=None,read_opener=None,region='na',audit=None):
    # Owner/target configuration is trusted operator input, never MCP input.
    if not isinstance(owner,str) or not owner or not isinstance(target,str) or not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}',target) or region not in ('na','eu','cn'):
        raise SafeError('Trusted local owner/vehicle configuration required')
    backend=backend or MacKeychain()
    try:client=credentials(backend.get('tesla-client'))
    except Exception:raise SafeError('Protected Tesla client credentials unavailable') from None
    store=PrivateStore(state_directory)
    vault=KeychainTokenVault(backend,owner)
    oauth=OAuthClient(store,owner,client['client_id'],client['client_secret'],vault=vault,
                      transport=oauth_transport,verifier=oidc_verifier,region=region,audit=audit)
    budget=DurableBudget(store,owner) # Zero by default. Operator alone configures allowance.
    def authorized_read(endpoint):
        token=oauth.access_token()
        scopes=vault.load().scopes
        required='vehicle_location' if endpoint=='location_data' else 'vehicle_device_data'
        if required not in scopes:raise SafeError('Required read permission unavailable')
        return target,token
    config=Config(mode='live-read',allow_live_reads=True,region=region)
    reader=FleetReader(config,credential_provider=authorized_read,budget=budget)
    # No network read adapter can silently activate from credential entry alone.
    if read_opener is None:
        class DisabledReads:
            def open(self,*args,**kwargs):raise SafeError('Read transport disabled pending approval')
        reader.opener=DisabledReads()
    else:reader.opener=read_opener
    return LocalRuntime(oauth,Service(config,reader),budget)
