# Implementation handoff checklist

Read `SECURITY-DESIGN.md` before changing code. This is a proposed next iteration, not evidence that these features exist.

## Establish the baseline

- Inspect actual repository state and obtain approval for a safe baseline commit/backup. The supplied handoff reports untracked files and no commits.
- Read actual `AGENTS.md`, storage/history contracts, SDK notes, and the pinned Go MCP SDK source. Do not infer API symbols from this document's sketches.
- Record the accepted threat model, newly authorized approval scope, supported authentication modes, and multi-call lease semantics in `docs/decisions.md`.

## Core security boundaries

- Authenticate the exact named caller access record on each call. A display suffix, browser label, IP, owner alone, or MCP session is not authority.
- Require a distinct interactive owner activation capability in all modes; extra confirmation/factors are configurable. Ordinary client/admin MCP keys cannot change MFA/recovery policy or approve themselves.
- Bind the immutable approval to caller, credential epoch, finite tool definitions, resource constraints, destination, duration, and gateway boot.
- Default to a timed working window with no call-count cap and no idle expiry. Never prompt for each permitted invocation.
- Recheck policy, visibility, epoch, runtime activation, time, and limits immediately before admission. Use the same short owner coordinator for revocation.
- Do not hold that coordinator during human approval, provider calls, or OAuth network refresh.
- Keep VRK and recovery material on the client. Release only the selected CEK; do not persist runtime CEKs or add a hidden server wrapper.
- Maintain separate durable approval/lease records and in-memory activation. Restart locked; never extend a lease through replay or duplicate activation.

## Integrations

- Add fallible secret resolution separately from coherent error-free metadata reads.
- Preserve existing stable IDs, owner boundaries, hidden-tool behavior, verifiers, audit hash bytes, and no-automatic-retry policy.
- Implement selected-field AEAD with strict, versioned, context-bound AAD. Use a reviewed canonicalizer for general RFC 8785 objects.
- Add PostgreSQL transaction boundaries and single-active execution ownership. Candidate SQL needs application-specific fields and actual execution tests.
- Add setup/discovery authorization so connector inspection does not silently bypass locked credentials.
- Serialize OAuth refresh before the provider request; encrypt/store the returned revision under CAS. Ordinary refresh does not require a new approval.
- Implement `none` and first-party `confirm` without external dependencies. Add Web Push or local TOTP only when selected; separate delivery, verification, and key release. Bind factor proof to requests and consume it once.
- Keep push off by default. An explicitly enabled notification-on-request preference is deduplicated and rate-limited; no notification event grants access. Protect disabling required verification with the current owner security policy.
- Bind all credential-bearing outbound destinations; test DNS/redirect/OAuth-discovery SSRF and stdio process isolation.

- Record actual authorization source and policy revision; never label disabled approval as successful MFA.
- Apply required-mode changes atomically: stale pending decisions, revoke affected leases, and preserve history.

## Audit and UX

- Log full public client-key ID plus immutable access ID, credential ID/epoch/revision, approval, lease, invocation, and stable tool identity.
- Show a short suffix of the public ID, not of the authentication secret or upstream token.
- Persist admission before dispatch; append completion separately. Unknown completion does not imply safe retry.
- Never log raw arguments/results, private headers, tokens, CEKs, challenge codes, or raw provider errors.
- Distinguish browser lock, execution lock, expired lease, unavailable provider, and approved-but-not-activated states.
- Make “Allow for 15 minutes” and “Stop access” ordinary first-class actions. Renewal is explicit; browser unlock may persist separately.

## Release gate

Implement the 68 acceptance cases in §22. Run actual project build/vet/race/UI and deployment tests, plus enabled push/OTP integrations, PostgreSQL, recovery, migration, and restore tests. Record results in `docs/progress.md`. Do not call the release client-encrypted while any converted credential still has an undisclosed permanent server unwrap route.
