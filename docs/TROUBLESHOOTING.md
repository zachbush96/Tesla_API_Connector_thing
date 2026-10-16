# Development sequence and troubleshooting

The reusable development sequence was synthetic read/preview MCP, strict broker/owner identity separation, OAuth and signed identity validation, protected refresh, exact command schemas and durable allowances, loopback TLS signing with the official SDK, bounded session/command phases, private gateway filtering, then a larger typed catalog. Private deployment artifacts and raw reports are excluded.

| Symptom | Lesson / safe next step |
| --- | --- |
| Consent appears successful but authorization is unavailable | Validate callback state and exact redirect/session, then signed ID token issuer/audience/nonce. Decoding a JWT is not verification. Keep full callbacks private. |
| Token kid is missing from published keys | Use the documented third-party JWKS. Bounded public-key refresh may handle rotation; never trim IDs or accept a nonmatching key. Do not repeat the single-use code exchange. |
| Refresh times out | Rotating-token outcome is uncertain. Durable refresh state requires fresh consent rather than an automatic retry with the old token. |
| Hosted key / positive paired-key count but commands fail | Neither proves this application's key is paired. Verify the matching key and domain/privileges under separate bounded diagnostic approval. |
| SECURITY handshake works, temperature fails | INFOTAINMENT is a separate session/domain. Handshake is not the final command. Account for each signed request and preserve the full SDK phase window. |
| 408/timeout despite adequate outer deadline | Check nested SDK deadlines and remaining phase windows. A shorter inner cutoff can abort a handshake. Keep no-retry behavior and retain reservations. |
| TLS works in one tool but fails in Go | Verify named-curve encoding, loopback IP SAN, matching TLS pair and certificate trust with your own keys. Never disable TLS verification. |
| Gateway sees 401/403 or wrong mode | Check distinct machine capability, verified owner identity, Access routing policy and consistent mock/live modes. Authentication remains separate from approval. |
| Worker invocation error | Preserve the runtime fetch receiver using an arrow wrapper around globalThis.fetch. Return fixed diagnostic categories, not exceptions. |
| Discovery works but chat has no tools | Discovery and actual tool invocation are different checks. Refresh the installed plugin connection and inspect schemas/protocol version. A setup page does not verify the vehicle. The included browser-discovery bridge carries the completed repair. |
| Typed tool exists but vehicle rejects it | Schema implementation is not hardware/firmware support. Consult prerequisites and label support unverified until a separately authorized test. |
| Command accepted | Report accepted only. Require owner observation or a separately approved bounded read before claiming a physical effect. |

Do not log bearer headers, precise destinations, VINs, callbacks, raw upstream bodies or identifying local paths. Runtime audit output stays private too: hashes and timestamps can correlate installations. Share only a fixed error category and minimal context when asking for help.
