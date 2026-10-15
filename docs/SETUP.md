# Set up for a different owner

## 1. Start offline

Use a fresh checkout and Python 3.11+. Run the README's offline commands. The mock needs no account, credentials, dependency install or network. In examples/mcp-client.json, replace PROJECT_DIRECTORY with your clone's absolute path in your MCP client's private configuration.

    python3 -m venv .venv
    # Optional live/OIDC dependencies only:
    .venv/bin/python -m pip install -r requirements-live.txt

Pinned Python dependencies are a reproducible baseline, not a review of current advisories. Review upstream advisories before a live installation.

## 2. Create your application and private configuration

Follow Tesla's [Fleet onboarding](https://developer.tesla.com/docs/fleet-api/getting-started/what-is-fleet-api), [authentication overview](https://developer.tesla.com/docs/fleet-api/authentication/overview), and [third-party token flow](https://developer.tesla.com/docs/fleet-api/authentication/third-party-tokens). Use your own Tesla application and domain. Configure the exact redirect URI https://YOUR_DOMAIN/oauth/callback. Check current account eligibility, regional endpoints, requested scopes and billing in your Tesla account.

Set nonsecret TESLA_CONNECTOR_PUBLIC_ORIGIN in the broker environment to your canonical HTTPS origin, with no path or trailing slash. Callback and broker host checks derive from that same origin. Do not use .invalid examples for real consent. Keep real configuration outside this clone; no real .env belongs in the repository.

Prepare TWO NEW owner-private directories outside your checkout:

    python3 scripts/prepare_private.py --state-dir /absolute/private/state --secrets-dir /absolute/private/secrets
    python3 enter_tesla_credentials.py

Replace both example paths. Preparation creates fresh broker capabilities and directories only, and refuses existing paths. Credential entry uses hidden input in your own Terminal and writes your client ID/secret to the new macOS Keychain namespace. It does not read the dashboard, copy a clipboard, exchange codes or contact a vehicle. Linux/Windows need an alternative secure credential backend.

## 3. Create and enroll your own virtual key

Follow the [virtual-key guide](https://developer.tesla.com/docs/fleet-api/virtual-keys/developer-guide). Generate a NEW prime256v1 signing key in your private directory with umask 077, derive the public key and host ONLY that public key at /.well-known/appspecific/com.tesla.3p.public-key.pem on your domain. Keep the private key offline from the public host. Tesla's guide provides the exact OpenSSL commands.

Obtain your own partner token and register your application's domain in each required region. This is an owner-authorized network step, not part of the offline tools. Complete owner consent and public-key enrollment using Tesla's documented mobile-app pairing flow. Confirm the correct vehicle privately. Registration, OAuth success, total paired-key count or a hosted key do not prove that your particular key has command privileges on your vehicle.

## 4. Obtain minimal consent locally

With your origin configured, the optional runner supports:

    .venv/bin/python run_live_broker.py --state-dir /absolute/private/state --secrets-dir /absolute/private/secrets --region na --setup-offline

This explicitly opens consent and exchanges an OAuth code; it does not issue a vehicle request. Use a private interactive Terminal and paste the complete callback into its hidden prompt only. Never paste callbacks into chat. The bootstrap supports manually copying the resulting callback even if its page cannot load.

The --setup option omits refresh permission. --setup-controls requests command/charging scopes and refresh permission; --setup-location additionally requests location. Review those permissions first. Reuse valid saved authorization instead of repeating consent unnecessarily. Tokens stay in your new Keychain namespace; only your own VIN goes into your private state directory.

A hosted callback requires a protected owner browser session. The public export does not provision that hosting/session frontend.

## 5. Compose a private installation before live testing

Read run_live_broker.py --help. Starting without a setup flag composes saved owner configuration and a renewal thread. It does not itself read the vehicle, but authorized tool calls can. Read allowance starts at zero. --monthly-read-budget-microdollars explicitly changes it. Review current Tesla billing before authorizing an amount. Reservation constants are conservative application policy, not guaranteed Tesla prices.

Commands additionally require a durable total cap, configured through DurableBudget.configure_total in a trusted local operator flow. compose_configured_controls refuses a missing cap or one above its conservative ceiling of 100000 microdollars. The monthly option alone does not enable commands. Never silently raise caps, refund uncertain requests or delete journals to regain allowance.

Build the signer with the Go version required by signer/go.mod and its dependencies:

    mkdir -p .private
    cd signer
    go mod download
    go build -trimpath -o ../.private/disabled ./cmd/disabled
    go build -trimpath -o ../.private/local-signer ./cmd/local-signer
    go build -trimpath -o ../.private/live-signer ./cmd/live-signer

Module downloads are public dependency fetches, not Tesla calls. Dependencies are not vendored in this export. Preserve their licenses when redistributing binaries. The disabled entry point is inert. The local-signer entry point simulates SDK activity but requires NEW protected signing/TLS files. live-signer is physically disabled by default; its explicit pairing, infotainment and execution flags enable distinct potentially paid operations. Do not enable them simply to see if setup works.

Generate a separate TLS key/certificate for loopback IP 127.0.0.1, distinct from the vehicle signing key. Use examples/signer-service.json.example and control-service.json.example as schemas. Replace placeholders privately; directories must be 0700 and config/key/token/certificate files 0600. Signer paths must be absolute, current-user owned, nonsymlink files with matching signing keys. The signer token_file must reference your NEW secrets directory's mcp.token, matching broker composition. Put signer-service.json and control-service.json in your new state directory.

The restricted LIVE signer pins North America. EU/CN read configuration exists; live commands there require a reviewed signer adaptation.

Deploy gateway/sites-gateway.mjs only behind a platform that supplies verified Sites owner identity. Configure BROKER_URL, OWNER_USER_ID, IDENTITY_BOUNDARY=sites, BROKER_GATEWAY_TOKEN, ACCESS_CLIENT_ID and ACCESS_CLIENT_SECRET through protected platform settings. BROKER_URL must be your HTTPS /mcp endpoint. This public gateway is MOCK ONLY and refuses REMOTE_CONTROL_MODE=live: the inspected Site source retains earlier sixteen-action schemas and receipt estimates. Adapt and review it against the Python 43-action catalog and current receipt/budget contract before a live deployment. Keep the Site audience private. The example contains secret NAMES only. A generic public Worker trusting arbitrary identity headers is unsafe.

Provision your own protected tunnel/service identity. Route /mcp to loopback 8765 with machine authentication and validated origin protection. CF-Access-Client-* headers require your own Access policy; Python does not validate Access JWTs itself. Put a verified Access boundary or equivalent in front of it and prevent bypass. The internal signer callbacks must never be public. The signer listens on loopback 8766 with TLS and its own capability.

Before remote human approval, supply an independent authenticated browser review UI with exact safe rendering and CSRF/replay protection; it is not bundled. Review ARCHITECTURE.md. Never expose the human approval capability to the model.

After consent, pairing, trust boundaries, budget and command-specific prerequisites are checked, authorize ONE exact bounded live test. The model may prepare; the owner independently approves. Execute within expiry. Request acceptance is not physical verification. An uncertain result ends the test and requires private reconciliation before any new approval. This release has not verified a new live installation.

## Official references

* [Fleet API onboarding](https://developer.tesla.com/docs/fleet-api/getting-started/what-is-fleet-api)
* [Authentication types/scopes](https://developer.tesla.com/docs/fleet-api/authentication/overview)
* [Third-party OAuth](https://developer.tesla.com/docs/fleet-api/authentication/third-party-tokens)
* [Virtual keys and enrollment](https://developer.tesla.com/docs/fleet-api/virtual-keys/developer-guide)
* [Vehicle command endpoints/prerequisites](https://developer.tesla.com/docs/fleet-api/endpoints/vehicle-commands)
* [Official Vehicle Command SDK, proxy and signing](https://github.com/teslamotors/vehicle-command)

Recheck current Tesla documentation and account requirements before live setup.
