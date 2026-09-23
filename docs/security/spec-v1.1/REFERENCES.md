# Technical references


The version 1.0 reference catalogue is preserved from the supplied specification. The additional first-party push, OTP, and factor-management sources R35–R40 were checked for this revision on **22 September 2026**; the remaining sources were not independently rechecked during this targeted revision. They are primary project documentation, official standards, or official security guidance. They support the named mechanisms; they do not certify this proposed implementation. Product defaults, schema design, state transitions, and proposed APIs are mcpwarden design decisions.

The handoff is the only evidence for the current local repository. Published SDK documentation is not a substitute for inspecting its pinned local module. No local mcpwarden source code, live approval-provider integration, production database, or deployment was exercised while writing this document.

| ID | Primary source | Relevant implementation topic |
|---|---|---|
| P0 | [mcpwarden current-state handoff, 2026-09-22](sources/mcpwarden-current-state-2026-09-22.md) | Current architecture, repository/audit contracts, auth modes, limitations, SDK pin, and invariants. Section references in the design refer to this document. |
| R01 | [Vaultwarden: Enabling HTTPS](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS) | HTTPS/reverse-proxy and web-vault secure-context precedent. |
| R02 | [Vaultwarden: Using the PostgreSQL Backend](https://github.com/dani-garcia/vaultwarden/wiki/Using-the-PostgreSQL-Backend) | PostgreSQL support as persistence, not a replacement for client encryption. |
| R03 | [Bitwarden Security White Paper](https://bitwarden.com/help/bitwarden-security-white-paper/) | Client key hierarchy, encrypted vault storage, key handling and memory limitations. |
| R04 | [Bitwarden: Log in with device](https://bitwarden.com/help/log-in-with-device/) | Adjacent approval-driven key transfer; requesting-device public key and fingerprint verification. |
| R05 | [MCP 2026-07-28: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Tool-call/results contracts, metadata, schema compatibility, and multi-round-trip behavior. mcpwarden leases are application policy, not a new MCP standard. |
| R06 | [MCP 2026-07-28: Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), and [2025-11-25 compatibility baseline](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Request-oriented current transport versus older session behavior; negotiation and compatibility testing. |
| R07 | [MCP 2026-07-28: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Resource-server token validation, audience/scopes, per-request authentication, and HTTP error boundaries. |
| R08 | [Official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) | Published compatibility table and SDK entry point. Inspect the actual pinned module before patching callbacks/transports. |
| R09 | [MCP: Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Token handling, OAuth discovery, SSRF, local execution and gateway trust boundaries. |
| R10 | [OWASP: Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) | Bind consent to significant details and check immediately before execution. This proposal deliberately authorizes a bounded working window; the reference does not certify blanket multi-call consent. |
| R11 | [Cisco Duo Auth API](https://duo.com/docs/authapi) | Historical optional-adapter reference only; not required by the core or a release gate. |
| R12 | [Cisco Duo: Policy & Control](https://duo.com/docs/policy) | Historical optional-adapter reference only; no mandatory vendor policy. |
| R13 | [Duo Go API client](https://github.com/duosecurity/duo_api_golang) | Optional future integration reference; not a required Go dependency. |
| R14 | [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) | Argon2id parameters and reference test vectors; lower-memory recommended profile used as a benchmark candidate. |
| R15 | [W3C Web Cryptography API](https://www.w3.org/TR/webcrypto/) | AES-GCM/HKDF browser primitive semantics and CryptoKey behavior. Argon2 is not supplied by this API. |
| R16 | [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html) | Deterministic approval/AAD encoding; not a silent change to the existing audit argument-hash format. |
| R17 | [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) | Domain-separated key derivation for wrapping keys. |
| R18 | [Go `crypto/cipher`](https://pkg.go.dev/crypto/cipher) | AEAD/GCM API, nonce handling, and random-nonce usage limits. Fixture tests use explicit nonces only for deterministic interoperability testing. |
| R19 | [Go `time`](https://pkg.go.dev/time) | Monotonic versus wall-clock deadlines; serialization and system sleep caveats. |
| R20 | [PostgreSQL: Date/time functions](https://www.postgresql.org/docs/current/functions-datetime.html) | Actual clock versus transaction-start timestamps during expiry checks. |
| R21 | [PostgreSQL: Explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html) | Row locking and session advisory locks; lock ordering and active-instance coordination. |
| R22 | [PostgreSQL: Transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html) | Concurrent transitions, conditional updates, serialization failures, and safe database-only retries. |
| R23 | [PostgreSQL: Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Defense-in-depth tenant filtering and privileged-role bypass considerations. |
| R24 | [PostgreSQL: NOTIFY](https://www.postgresql.org/docs/current/sql-notify.html) | Cache wakeups; not a complete durable distributed authorization-consistency mechanism. |
| R25 | [PostgreSQL: pgcrypto](https://www.postgresql.org/docs/current/pgcrypto.html) | SQL-side crypto runs inside the database trust boundary; not client-only encryption. |
| R26 | [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Actor/action attribution, sensitive-data exclusion, integrity, access and retention. |
| R27 | [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | Browser policy and script/supply-chain hardening. |
| R28 | [OWASP: Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | CSRF tokens, origin validation and cookie-authenticated approval/activation endpoints. |
| R29 | [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) | Refresh-token protection, replay defenses, binding and OAuth security requirements. |
| R30 | [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) | PRF extension and handling sensitive extension outputs; optional later vault-unlock mechanism. |
| R31 | [OWASP: MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | Prompt/tool injection, excessive agency, transport and intermediary risks. |
| R32 | [Go `golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) | Reference implementation for local/offline testing of Argon2id parameters. |
| R33 | [OWASP: Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | TLS versions, termination and application transport hardening. |
| R34 | [OWASP: Server-Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Destination validation, DNS/redirect handling and explicit network allowlists. |
| R35 | [W3C Push API](https://www.w3.org/TR/push-api/) | Browser subscriptions, service workers, permission, and delivery-service roles; the retrieved publication is a Working Draft, so feature-test actual browsers. |
| R36 | [RFC 8030: Generic Event Delivery Using HTTP Push](https://www.rfc-editor.org/rfc/rfc8030.html) | Web Push delivery, message TTL, subscription and delivery lifecycle. |
| R37 | [RFC 8291: Message Encryption for Web Push](https://www.rfc-editor.org/rfc/rfc8291.html) | Push payload encryption; independent of credential-vault encryption and approval evidence. |
| R38 | [RFC 8292: VAPID for Web Push](https://www.rfc-editor.org/rfc/rfc8292.html) | Sender identification to the push service; not user authentication or vault key release. |
| R39 | [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238.html) | Local authenticator OTP, shared-secret verification, reference vectors, clock skew, and successful-code replay rejection. |
| R40 | [OWASP: Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) | Distinguish confirmation from MFA; protect factor changes and recovery; avoid silent downgrade and push fatigue. |

