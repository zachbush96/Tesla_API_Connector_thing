# Architecture and trust boundaries

    MCP client -> private gateway -> protected tunnel -> loopback Python broker
                                                       | OAuth + Keychain
    Human -> trusted review UI -> exact one-use grant --| durable SQLite journal
                                                       | loopback TLS
                                                       v
                                                  restricted Go signer
                                                       | official Tesla SDK
                                                       v
                                                  Fleet API -> vehicle

The runnable stdio demo stops at synthetic reads/previews. Live arrows describe the reference components after a new owner composes them; this repository creates no hosted service or trusted human review UI.

* service.py filters three read endpoints, bounds responses, refuses redirects and never wakes/retries. Coarse location remains sensitive. Config defaults to mock.
* oauth.py, oidc.py and oauth_transport.py bind state/session/nonce, validate signed identity and protect rotating refresh state. No tokens or upstream exceptions belong in model output. Keychain service tesla-connector-fleet isolates this export from other installations. Other operating systems need a secure backend, not plaintext token export.
* controls.py and control-catalog.json build fixed payloads. commands.py is the earlier two-command adapter with a disabled default transport. The broader workflow uses remote_controls.py, execution_grants.py and live_controls.py.
* A prepared operation is a proposal. Only a trusted human boundary approves the exact owner, target, action and canonical payload. Approval expires, is single use and is consumed before transmission.
* storage.py reserves gross spending durably. Timeout after transmission is uncertain, consumes authority, retains its debit and must not be retried automatically. Cancellation/deadlines propagate through journal, bridge, TLS and SDK phases.
* signer/ revalidates canonical bindings, constrains commands/targets, checks command-specific facts and accounts for each signed/network attempt. A handshake can consume network budget without a physical action.
* gateway/worker.mjs trusts oai-authenticated-user-id only behind a verified Sites boundary. A header supplied by an arbitrary Internet client is not identity. OWNER_USER_ID, routing credentials and BROKER_URL are trusted settings. Replacing Sites requires an authentication adapter.

Keep public-key hosting, owner browser access and machine MCP ingress separate. A public key is not a private key; a tunnel credential is not Tesla consent. The Site audience must remain owner-private even though this source is public.

The original browser review frontend is not bundled. Before enabling remote approval, implement a frontend that independently authenticates the human, safely displays the exact review and protects approval POSTs against CSRF/replay. Never expose browser_approve_control to the model or let an LLM click Approve for the owner. OperatorConsole and OwnerControlWorkflow illustrate local review but are not a drop-in frontend for RemoteOperations.

The inspected Site source retains the older sixteen-action gateway contract. The public adapter rejects live mode rather than forwarding mismatched schemas or old receipt estimates. A live gateway and human review frontend remain new-owner integration work.
