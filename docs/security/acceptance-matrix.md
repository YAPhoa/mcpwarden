# Spec v1.1 acceptance matrix

Status of the 68 acceptance cases in
[SECURITY-DESIGN.md §22](spec-v1.1/SECURITY-DESIGN.md#22-acceptance-tests),
checked against the repository on 2026-09-23. Test names are Go test functions
unless marked as UI tests (`ui/tests/`). Update a row when its evidence changes.

Status meanings:

- **Live**: enforced by the running gateway and covered by tests.
- **Library**: passes in package or SDK/PostgreSQL integration tests, but startup
  does not install that path yet, so the deployed gateway does not enforce it.
- **Partial**: part of the case is tested; the gap column says what is missing.
- **Open**: no implementation or test yet.
- **Unselected**: depends on push, TOTP or step-up modules that remain optional
  and unselected (M3 does not block a core `none`/`confirm` release).

Totals: 3 Live, 27 Library, 26 Partial, 5 Open, 7 Unselected.

## 22.1 Multi-call workflow and time

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| L01 | Library | `TestWorkingWindowRepeatedCallsAndFixedExpiry`; `TestEncryptedDispatchThroughMCPAndPostgres` runs 25 calls under one window | Startup wiring; owner UI to open the window |
| L02 | Partial | `TestResourceConstraints`, `TestEncryptedDispatchThroughMCPAndPostgres` (varying arguments within constraints) | No test chains an earlier result into a later call's arguments |
| L03 | Library | `TestEncryptedDispatchThroughMCPAndPostgres` (reconnects through both views; second key cannot borrow) | Startup wiring |
| L04 | Library | `TestConcurrencyRejectsAndUnusedAdmissionExpires`, `TestBudgetAdmissionAtomicAndConcurrency` | Load qualification |
| L05 | Library | `TestConcurrencyRejectsAndUnusedAdmissionExpires` (delayed permit after expiry is not dispatched) | Startup wiring |
| L06 | Library | `TestActivationCommitFailureAndExpiredConfirmation`, `TestActivationClockAndOwnerExpiryDuringStage` | Owner UI flow |
| L07 | Library | `TestWorkingWindowRepeatedCallsAndFixedExpiry` (traffic does not move the deadline) | Startup wiring |
| L08 | Library | `TestRenewalBrowserClosureAndExecutionLock` | Visible deadline in the owner UI |
| L09 | Library | `TestRenewalBrowserClosureAndExecutionLock` | Browser lock and execution-lock controls in the UI |
| L10 | Library | `TestRevocationDoesNotHoldGateAcrossNetwork`, `TestPreparationDrainsOnRevocationAndRechecksBeforeDispatch`, `TestMaterialRechecksClockAndCallerAtInjection` | Startup wiring |
| L11 | Library | `TestClockDiscontinuityRestartAndLostLock`, `TestPostgresClockAfterOwnerLock`, `TestPostgresSnapshotRestartLocksExecution` | Suspend/resume on real hosts |
| L12 | Library | `TestBudgetAdmissionAtomicAndConcurrency`, `TestPostgresAtomicBudget` | Startup wiring |

## 22.2 Identity and authorization

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| A01 | Library | `TestCallerExpiryOwnerIsolationAndRequestLimits`, `TestPostgresDurabilityIsolationAndPrivileges` | Owner HTTP routes do not exist yet |
| A02 | Library | `TestExactCallerScopeAndMutation`, `TestEncryptedDispatchThroughMCPAndPostgres` | Startup wiring |
| A03 | Live | `TestNamedKeyMintAndAuthenticationPaths`, `TestLegacyAuthenticationHashesDoNotEnterAuditActor`, `TestAccountsWorkspaceIsolationAndClientTokens` | Legacy operator and storeless OAuth modes report actor type only |
| A04 | Partial | `TestOwnerActivationAndReplay`, `TestEncryptedDispatchThroughMCPAndPostgres` (MCP caller cannot activate itself) | Fresh interactive authentication on owner routes; factor enrollment is unselected |
| A05 | Library | `TestRejectUnsupportedScope`, `TestResourceConstraints`, `FuzzParseScope` | Startup wiring |
| A06 | Library | `TestNoUnionAndCurrentToolPolicy` | Startup wiring |
| A07 | Library | `TestResourceConstraints` (changed definition), `TestEncryptedDispatchThroughMCPAndPostgres` (definition drift) | Startup wiring |
| A08 | Library | `TestNoUnionAndCurrentToolPolicy`, `TestPreparationDoesNotSwitchToAnotherLease` | Startup wiring |
| A09 | Partial | `TestAccessCapsRevocationAndMigration`, `TestAccessRolesAndRevocableMCPSessions`, `TestChangePasswordRequiresCurrentAndRevokesOtherBrowsers` | Revocation is not yet routed through the owner coordinator |
| A10 | Partial | UI test "workspace shows server identity and clearly labels shared operator mode" | Owner-specific caller authorization for shared upstreams under leases |

## 22.3 Cryptography and lifecycle

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| C01 | Library | `TestPublishedEnvelopeVector`, `TestWebCryptoInteroperability`, `TestBrowserVaultWrapperInteroperability` | None for primitives; product flows unwired |
| C02 | Library | `TestActivationAuthenticatesBundleAndClearsOwnedBuffers`, UI test "credential wrappers and envelopes reject replay across every binding" | None for primitives |
| C03 | Library | `TestEnvelopeStrictParsing`, `TestStrictWrapperParsing`, `FuzzEnvelope`, UI tests on strict JSON and unsupported KDFs | None for primitives |
| C04 | Partial | `TestVaultNonceBindingsAndWrappingKeyCap`, `TestVaultWriteCapAndBindingConstraints` | Browser production encryption path is not wired to storage |
| C05 | Partial | `TestEncryptedDispatchThroughMCPAndPostgres` stores only ciphertext | No scan of real database dumps and backups |
| C06 | Library | `TestPreparationIsScopedAndCannotRetainOrDispatchMaterial`, UI test "setup, passphrase unlock, selected CEK release…" | Owner release route |
| C07 | Library | `TestPostgresSnapshotRestartLocksExecution`, `TestClockDiscontinuityRestartAndLostLock` | Startup wiring |
| C08 | Partial | UI test "setup, passphrase unlock, selected CEK release, rewrap and recovery preserve bindings" | Root rotation, CEK epoch rotation and upstream credential rotation (step 7) |
| C09 | Partial | Same UI test (recovery-key unlock) | Account reset without the recovery key is not tested |
| C10 | Partial | `TestExactCallerScopeAndMutation` (epoch change), `TestMaterialRevisionCannotBeMisreported` | OAuth refresh revisions (step 6) |
| C11 | Partial | `TestPostgresSnapshotRestartLocksExecution` | Stale-snapshot freshness and full restore drill (step 9) |

## 22.4 Optional approval, transport, OAuth, and isolation

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| D01 | Partial | `TestOwnerActivationAndReplay` (`confirm` bound to request digest) | Factor proofs are unselected |
| D02 | Unselected | Not applicable while no delivery or factor adapter is enabled | Needed only if push or TOTP is selected |
| D03 | Unselected | Not applicable | Needed only if push or TOTP is selected |
| D04 | Partial | `TestCallerExpiryOwnerIsolationAndRequestLimits` (request caps and deduplication) | Push rate limits are unselected |
| D05 | Partial | `TestOriginValidation`, `TestBearerAndOrigin` for the existing admin API | Owner activation routes, CSRF and cache headers (step 1) |
| D06 | Partial | `TestDialChecksAllAnswersAndPinsCheckedIP`, `TestDestinationIPPolicy`, `TestOAuthRejectsInsecureDiscoveredEndpoint` | Legacy HTTP transport lacks connection-time IP checks; OAuth endpoint SSRF (step 8) |
| D07 | Partial | `TestStdioChildEnvironment` (only allowlisted variables reach stdio children) | Process and host isolation (step 8) |
| D08 | Open | None | Serialized OAuth refresh (step 6) |
| D09 | Open | None | Refresh-token rotation crash handling (step 6) |
| D10 | Library | `TestEncryptedDispatchThroughMCPAndPostgres` (both protocol revisions; locked calls respect output schemas) | Startup wiring |
| D11 | Partial | `TestLegacyAuthenticationHashesDoNotEnterAuditActor`, `TestNamedKeyMintAndAuthenticationPaths` | No review of new MCP metadata pathways or access-log contents |

## 22.5 Persistence, audit, and migration

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| P01 | Library | `TestPostgresDurabilityIsolationAndPrivileges`, `TestVaultRecordsCASIsolationAndRetention` | Full PostgreSQL catalog (step 3) |
| P02 | Live | `TestDispatchAuditFailuresNeverCauseExecutionOrReplay`, `TestAdmissionUnknownUntilCompletionAcrossRestart`, `TestPostgresAdmissionCommitFailure` | None for the file-audit path |
| P03 | Partial | `TestEncryptedDispatchThroughMCPAndPostgres` (no private data in diagnostics) | Panic paths, SQL diagnostics and support exports |
| P04 | Partial | `TestLeaseAttributionIsAnAtomicMetadataBundle`, `TestEncryptedDispatchThroughMCPAndPostgres` | Live calls do not carry credential epoch, lease or approval yet |
| P05 | Live | `TestInvocationImportOrderOwnerIsolationAndLegacyPreservation`, `TestStableToolIdentity`, UI test "public key handles disambiguate collisions…" | None |
| P06 | Library | `TestOwnerActivationAndReplay`, `TestPostgresAmbiguousActivationCommit` | Owner routes |
| P07 | Partial | `TestLegacyPublicIDMigrationPreservesCredentialsAndLifecycle`, `TestMigrationV1UpgradeAndRollback` | File-to-PostgreSQL catalog and history migration (step 9) |
| P08 | Partial | `TestPostgresSnapshotRestartLocksExecution` | Revocation and token-rotation reconciliation after restore (step 9) |
| P09 | Library | `TestPostgresExclusiveExecutorAndLoss` | Startup wiring |
| P10 | Library | `TestPostgresDurabilityIsolationAndPrivileges` | Retention role and procedure |
| P11 | Partial | `TestBudgetAdmissionAtomicAndConcurrency`, `TestPostgresAtomicBudget` | High-concurrency load tests (step 10) |
| P12 | Partial | `TestAtomicVaultCommitFailureDoesNotPublish`, `TestAtomicVaultMutationRevokesOnlyAfterCommit` | Catalog mutations do not go through the coordinator yet (step 3) |

## 22.6 Optional-mode acceptance cases

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| O01 | Partial | `TestOwnerActivationAndReplay` | Owner release flow in the UI (steps 1–2) |
| O02 | Partial | `TestOwnerActivationAndReplay` (`confirm` decisions) | In-app inbox UI (step 2) |
| O03 | Unselected | Not applicable | TOTP and push are unselected |
| O04 | Partial | `TestOwnerActivationAndReplay`, `TestEncryptedDispatchThroughMCPAndPostgres` | Same checks through owner routes for every mode |
| O05 | Unselected | Not applicable | Push is unselected |
| O06 | Unselected | Not applicable | Push is unselected |
| O07 | Open | None | Security-policy changes require an owner route (step 1) |
| O08 | Open | None | Policy change must stale pending decisions and revoke leases |
| O09 | Unselected | Not applicable | TOTP is unselected |
| O10 | Unselected | Not applicable | Push and TOTP are unselected |
| O11 | Open | None | Cross-owner proof substitution through owner routes |
| O12 | Partial | `TestPostgresSnapshotRestartLocksExecution` (restart locked); no push or OTP configuration exists | Cold restart through the real startup path (step 4) |
