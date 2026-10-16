# Tesla connector starter

A sanitized, owner-configured Tesla Fleet API / MCP connector. Start with an offline demo, then use the broker, OAuth, approval journal, gateway and restricted Go signer as a reference for your own private installation.

**Nothing in this repository is connected to a vehicle.** There are no deployed endpoints, keys, tokens, vehicle identifiers, owner identities, runtime databases or private deployment history. Example domains end in .invalid; test vehicles and credentials are synthetic. This is an independent project, not an official Tesla product.

## Try it offline

Requirements: Python 3.11+; Node 20+ for gateway examples; Go according to signer/go.mod and its dependencies. No dependency install is needed for the Python demo.

    python3 -B scripts/offline_smoke.py
    python3 -B run_server.py < examples/demo.txt
    python3 -B scripts/check_config.py

The stdio entry point always uses mock data, even if live-read environment variables exist. It exposes three filtered reads and two previews. A preview validates a request and never sends it. The Python reference broker exposes a broader workflow when explicitly composed. The gateway exposes the same 43 typed proposals and includes the owner browser review/approval UI. Mock mode remains the default; live mode requires your own completed private installation.

## Contents

| Path | Purpose |
| --- | --- |
| tesla_connector/ | Filtered reads, command schemas, OAuth/OIDC, macOS Keychain, durable budgets and single-use approval journals, loopback broker, signer bridge |
| gateway/ | Complete ESM gateway, 43-action schemas, browser setup and exact human approval UI; requires a verified Sites identity boundary |
| signer/ | Restricted Go wrapper around a pinned official Tesla Vehicle Command SDK; default mock and explicitly enabled live entry points |
| scripts/ | Offline checks and fresh local credential preparation |
| tests/ | Synthetic Python coverage; signer includes Go tests and cross-language bindings |
| examples/ | Generated, nonfunctional owner configuration templates |
| docs/ | Setup, architecture, supported commands, troubleshooting, and copyable LLM prompt |

Read [setup](docs/SETUP.md), [architecture](docs/ARCHITECTURE.md), [command support](docs/COMMANDS.md), [troubleshooting](docs/TROUBLESHOOTING.md), and the [LLM setup prompt](docs/LLM_SETUP_PROMPT.md).

## Limits and provenance

This export comes from the current source of a private prototype, with fresh history and generic configuration. Its deployment state, identities, tunnel credentials, automatic login jobs, native preview helper, owner-specific platform project metadata and raw verification reports are excluded. This is source for a new installation, not a portable authorization to an existing one.

The original integration exercised one signed temperature command end to end. That is historical implementation context, **not verification of this export or every command**. The expanded 43-action catalog describes implemented schemas and prerequisites; most individual vehicle effects and hardware/firmware combinations remain unverified. Publication used offline checks only.

Live activation is advanced integration work: supply your own Tesla application/domain, consent, virtual-key pairing, trusted human review boundary and reviewed allowance. Explicitly enable matching broker/signer/gateway modes only after that setup. OAuth or pairing alone never counts as command approval. The restricted live signer pins North America; other regions need a reviewed adaptation.

No license has been selected for original project code. Public visibility alone does not grant an open-source license. See [third-party notices](THIRD_PARTY_NOTICES.md).

## Offline verification

    python3 -B scripts/run_offline_tests.py
    node scripts/build_gateway.mjs
    node scripts/gateway_smoke.mjs
    cd signer && go test ./...

Python unit tests deny outbound socket connections. Gateway tests use injected fake fetch and forbid external network. Go tests use synthetic vehicle/credential fixtures and mocked Fleet transports; one test opens a local loopback HTTP listener. Dependency downloads may be needed before Go tests. Legacy SDK behavior cases cover the original sixteen actions; generated canonical-binding fixtures validate all 43 action schemas across Python and Go. These checks do not verify any new owner's vehicle or live hosting.

The gateway source and owner review UI come from the completed command-expansion implementation, including its navigation review and browser-discovery fixes. Run node scripts/build_gateway.mjs to produce ignored dist/gateway.mjs for your own platform. gateway/index.mjs is the equivalent multi-module entry point. Supply your own platform project metadata; no existing Site is embedded.
