# Validation and limitations — v1.1

Prepared 22 September 2026. This is a targeted documentation revision, not a security certification.

## Rerun successfully for this revision

The unchanged public synthetic credential-envelope fixture was encrypted/decrypted and checked again in three runtimes:

| Runtime | Actual environment | Result |
|---|---|---|
| Python | 3.13.5, cryptography 46.0.4 | PASS |
| Node WebCrypto | v22.16.0 | PASS |
| Go standard-library AES-GCM | go version go1.23.2 linux/amd64 | PASS |

Commands executed from this bundle root:

```sh
python tests/test_envelope.py
node tests/test_envelope.mjs
go run tests/test_envelope.go
```

The checks cover the fixed fixture's exact AAD/ciphertext/nonce/tag encoding, roundtrip, and rejection of wrong owner binding, altered tag, altered nonce, and wrong key. They do not validate the entire product. Deterministic public test inputs must never be reused as production keys or nonces. The test header encoding is deliberately limited to its fixed ASCII string-only object, not a general RFC 8785 canonicalizer.

## Documentation checks performed

Markdown fence structure and relative links, 25 numbered main sections, 68 distinct acceptance IDs, 40 numbered reference entries, YAML parsing, absence of a mandatory vendor provider in configuration/schema, preservation of the original handoff and crypto fixtures/tests, and ZIP integrity. Results are in `reference/document-checks.txt`.

These are artifact consistency checks, not SQL execution or application behavior tests. The base candidate schema still has 15 tables; `reference/approval-options.sql` sketches 3 optional policy/factor/subscription tables.

## Not executed or implemented

The base and optional SQL were not executed in PostgreSQL. No migrations, SQL race/privilege tests, live notifications, OTP verification/enrollment, browser automation, actual MCP interoperability, OAuth refresh, full key hierarchy, recovery, or gateway lifecycle tests ran.

No actual mcpwarden application source was audited or modified. No project SDK hooks were compiled. In particular, rerunning the standalone Go AES-GCM test does not validate the handoff's Go 1.27 application build.

The new 12 O-series acceptance cases are requirements for future implementation, not passing test results. Optional push/TOTP modules require their own standard fixtures and live tests before being enabled. A core release with those features off does not need a third-party approval account.

Only references R35–R40 were newly checked for this revision; the previous source catalogue is retained without an independent full re-review. Review all pinned dependency and protocol claims against the actual target repository before implementation.

## Required implementation validation

Run the selected §22 acceptance suites and the project's build, vet, race, UI, smoke, migration, and restore tests. Record actual results in `docs/progress.md`. Approval-off must not become authorization-off or a permanent server unwrap route.
