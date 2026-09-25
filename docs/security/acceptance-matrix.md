# Spec v1.1 acceptance matrix

Status of the 68 acceptance cases in
[SECURITY-DESIGN.md §22](spec-v1.1/SECURITY-DESIGN.md#22-acceptance-tests),
checked against the repository on 2026-09-25. Test names are Go test functions
unless marked as UI tests (`ui/tests/`). Browser flows are steps of
`ui/tests/owner-flows.mjs`, which drives the owner console against a real
gateway and PostgreSQL. Update a row when its evidence changes.

Status meanings:

- **Live**: enforced by the running gateway and covered by tests.
- **Opt-in**: served by the running gateway when `owner_security` is configured
  and covered by PostgreSQL integration tests of the real HTTP routes. Tool
  execution does not consult leases until guarded startup (roadmap step 4).
- **Library**: passes in package or SDK/PostgreSQL integration tests, but startup
  does not install that path yet, so the deployed gateway does not enforce it.
- **Partial**: part of the case is tested; the gap column says what is missing.
- **Open**: no implementation or test yet.
- **Unselected**: depends on push, TOTP or step-up modules that remain optional
  and unselected (M3 does not block a core `none`/`confirm` release).

Totals: 3 Live, 19 Opt-in, 20 Library, 17 Partial, 2 Open, 7 Unselected.

## 22.1 Multi-call workflow and time

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| L01 | Library | `TestWorkingWindowRepeatedCallsAndFixedExpiry`; `TestEncryptedDispatchThroughMCPAndPostgres` runs 25 calls under one window | Startup wiring |
| L02 | Partial | `TestResourceConstraints`, `TestEncryptedDispatchThroughMCPAndPostgres` (varying arguments within constraints) | No test chains an earlier result into a later call's arguments |
| L03 | Library | `TestEncryptedDispatchThroughMCPAndPostgres` (reconnects through both views; second key cannot borrow) | Startup wiring |
| L04 | Library | `TestConcurrencyRejectsAndUnusedAdmissionExpires`, `TestBudgetAdmissionAtomicAndConcurrency` | Load qualification |
| L05 | Library | `TestConcurrencyRejectsAndUnusedAdmissionExpires` (delayed permit after expiry is not dispatched) | Startup wiring |
| L06 | Library | `TestActivationCommitFailureAndExpiredConfirmation`, `TestActivationClockAndOwnerExpiryDuringStage`; browser flows start windows only after review and leave pre-restart requests unstartable | Startup wiring |
| L07 | Library | `TestWorkingWindowRepeatedCallsAndFixedExpiry` (traffic does not move the deadline) | Startup wiring |
| L08 | Opt-in | `TestRenewalBrowserClosureAndExecutionLock`; browser flow "unlock failures, then unlock and renew" (a new request and window with its own end time; the earlier window's expiry is unchanged); browser flow "renewal asks for a new review when a tool definition changed" (no key release until the changed scope is reviewed) | Guarded execution at startup (step 4) |
| L09 | Opt-in | `TestRenewalBrowserClosureAndExecutionLock`; browser flows (sign-out, Lock browser, leaving the page and idle lock keep windows; Lock all execution ends them) | Guarded execution at startup (step 4) |
| L10 | Library | `TestRevocationDoesNotHoldGateAcrossNetwork`, `TestPreparationDrainsOnRevocationAndRechecksBeforeDispatch`, `TestMaterialRechecksClockAndCallerAtInjection` | Startup wiring |
| L11 | Library | `TestClockDiscontinuityRestartAndLostLock`, `TestPostgresClockAfterOwnerLock`, `TestPostgresSnapshotRestartLocksExecution` | Suspend/resume on real hosts |
| L12 | Library | `TestBudgetAdmissionAtomicAndConcurrency`, `TestPostgresAtomicBudget` | Startup wiring |

## 22.2 Identity and authorization

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| A01 | Opt-in | `TestOwnerActivationReplayAndOwnerIsolation` (keys and other owners see only their own requests, windows and events), `TestCallerExpiryOwnerIsolationAndRequestLimits`, `TestPostgresDurabilityIsolationAndPrivileges` | Guarded execution at startup (step 4) |
| A02 | Library | `TestExactCallerScopeAndMutation`, `TestEncryptedDispatchThroughMCPAndPostgres` | Startup wiring |
| A03 | Live | `TestNamedKeyMintAndAuthenticationPaths`, `TestLegacyAuthenticationHashesDoNotEnterAuditActor`, `TestAccountsWorkspaceIsolationAndClientTokens` | Legacy operator and storeless OAuth modes report actor type only |
| A04 | Opt-in | `TestOwnerRoutesRequireInteractiveBrowserSession` (client and admin keys, and a key plus a browser cookie, cannot activate in mode `none`; policy and vault changes need the current password), `TestOwnerActivationAndReplay`, `TestEncryptedDispatchThroughMCPAndPostgres` | Factor enrollment is unselected |
| A05 | Library | `TestRejectUnsupportedScope`, `TestResourceConstraints`, `FuzzParseScope` | Startup wiring |
| A06 | Library | `TestNoUnionAndCurrentToolPolicy` | Startup wiring |
| A07 | Library | `TestResourceConstraints` (changed definition), `TestEncryptedDispatchThroughMCPAndPostgres` (definition drift) | Startup wiring |
| A08 | Library | `TestNoUnionAndCurrentToolPolicy`, `TestPreparationDoesNotSwitchToAnotherLease` | Startup wiring |
| A09 | Opt-in | `TestOwnerConcurrentMutationsAndKeyRevocation` (key revocation ends its window through the coordinator), `TestOwnerRoutesFailClosedOnDatabaseLoss` (key revocation and logout still succeed while storage is lost), `TestOwnerMutationsRejectRevokedSession`, `TestOwnerCredentialWriteRejectsReplacedSession`, `TestOwnerMutationRechecksSessionAfterDatabaseWait`, `TestAccessCapsRevocationAndMigration`, `TestAccessRolesAndRevocableMCPSessions`, `TestChangePasswordRequiresCurrentAndRevokesOtherBrowsers` | Without `owner_security` there are no windows to end |
| A10 | Partial | UI test "workspace shows server identity and clearly labels shared operator mode" | Owner-specific caller authorization for shared upstreams under leases |

## 22.3 Cryptography and lifecycle

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| C01 | Library | `TestPublishedEnvelopeVector`, `TestWebCryptoInteroperability`, `TestBrowserVaultWrapperInteroperability` | None for primitives; product flows unwired |
| C02 | Library | `TestActivationAuthenticatesBundleAndClearsOwnedBuffers`, UI test "credential wrappers and envelopes reject replay across every binding" | None for primitives |
| C03 | Library | `TestEnvelopeStrictParsing`, `TestStrictWrapperParsing`, `FuzzEnvelope`, UI tests on strict JSON and unsupported KDFs | None for primitives |
| C04 | Opt-in | `TestVaultNonceBindingsAndWrappingKeyCap`, `TestVaultWriteCapAndBindingConstraints`; browser flows encrypt and replace credentials in the worker and upload them through the owner API | None beyond guarded execution (step 4) |
| C05 | Partial | `TestEncryptedDispatchThroughMCPAndPostgres` stores only ciphertext | No scan of real database dumps and backups |
| C06 | Opt-in | `TestOwnerActivationReplayAndOwnerIsolation` (owner release route), `TestPreparationIsScopedAndCannotRetainOrDispatchMaterial`, UI test "setup, passphrase unlock, selected CEK release…"; browser flows (only `/activate` bodies carry a key; no request carries a passphrase, recovery key or credential value) | Guarded execution at startup (step 4) |
| C07 | Library | `TestPostgresSnapshotRestartLocksExecution`, `TestClockDiscontinuityRestartAndLostLock` | Startup wiring |
| C08 | Partial | UI test "setup, passphrase unlock, selected CEK release, rewrap and recovery preserve bindings"; browser flows change the passphrase (old one refused) and replace a credential as a new epoch under the same ID | Root rotation and upstream credential rotation (step 7) |
| C09 | Partial | Same UI test (recovery-key unlock); browser flows verify the typed recovery key before setup and unlock with it | Account reset without the recovery key is not tested |
| C10 | Partial | `TestExactCallerScopeAndMutation` (epoch change), `TestMaterialRevisionCannotBeMisreported` | OAuth refresh revisions (step 6) |
| C11 | Partial | `TestPostgresSnapshotRestartLocksExecution` | Stale-snapshot freshness and full restore drill (step 9) |

## 22.4 Optional approval, transport, OAuth, and isolation

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| D01 | Partial | `TestOwnerActivationAndReplay` (`confirm` bound to request digest) | Factor proofs are unselected |
| D02 | Unselected | Not applicable while no delivery or factor adapter is enabled | Needed only if push or TOTP is selected |
| D03 | Unselected | Not applicable | Needed only if push or TOTP is selected |
| D04 | Partial | `TestOwnerSecurityRequestLimitsAndBodies` (per-key route budget, body and duration caps), `TestCallerExpiryOwnerIsolationAndRequestLimits` (request caps and deduplication) | Push rate limits are unselected |
| D05 | Opt-in | `TestOwnerRoutesRequireInteractiveBrowserSession` (CSRF, Origin, fetch metadata, JSON and no-store), `TestOwnerRejectsInsecureExternalActivation` (forged HTTPS headers rejected before CEK body reads), `TestOwnerTransportTrust` (explicit trusted proxies and direct-loopback development), `TestOriginValidation`, `TestBearerAndOrigin`; browser flows (cookie-only owner requests with CSRF, no-store, untrusted-transport state) | Verified production TLS ingress before enabling the API |
| D06 | Partial | `TestDialChecksAllAnswersAndPinsCheckedIP`, `TestDestinationIPPolicy`, `TestOAuthRejectsInsecureDiscoveredEndpoint` | Legacy HTTP transport lacks connection-time IP checks; OAuth endpoint SSRF (step 8) |
| D07 | Partial | `TestStdioChildEnvironment` (only allowlisted variables reach stdio children) | Process and host isolation (step 8) |
| D08 | Open | None | Serialized OAuth refresh (step 6) |
| D09 | Open | None | Refresh-token rotation crash handling (step 6) |
| D10 | Library | `TestEncryptedDispatchThroughMCPAndPostgres` (both protocol revisions; locked calls respect output schemas) | Startup wiring |
| D11 | Partial | `TestLegacyAuthenticationHashesDoNotEnterAuditActor`, `TestNamedKeyMintAndAuthenticationPaths` | No review of new MCP metadata pathways or access-log contents |

## 22.5 Persistence, audit, and migration

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| P01 | Opt-in | `TestPostgresDurabilityIsolationAndPrivileges`, `TestVaultRecordsCASIsolationAndRetention`, `TestImportPreservesCatalogAndHistory`, `TestRepositoryCommitsAtomicallyAndFailsClosed`, `TestOwnerFlowsOnPostgresCatalog` | Live data still on the file catalog |
| P02 | Live | `TestDispatchAuditFailuresNeverCauseExecutionOrReplay`, `TestAdmissionUnknownUntilCompletionAcrossRestart`, `TestPostgresAdmissionCommitFailure` | None for the file-audit path |
| P03 | Partial | `TestEncryptedDispatchThroughMCPAndPostgres` (no private data in diagnostics) | Panic paths, SQL diagnostics and support exports |
| P04 | Partial | `TestLeaseAttributionIsAnAtomicMetadataBundle`, `TestEncryptedDispatchThroughMCPAndPostgres` | Live calls do not carry credential epoch, lease or approval yet |
| P05 | Live | `TestInvocationImportOrderOwnerIsolationAndLegacyPreservation`, `TestStableToolIdentity`, UI test "public key handles disambiguate collisions…" | None |
| P06 | Opt-in | Browser flows (an uncertain activation retries with the same Idempotency-Key and yields one window), `TestOwnerActivationReplayAndOwnerIsolation` (identical retry returns the same window; a new operation is refused), `TestOwnerConcurrentMutationsAndKeyRevocation` (parallel activations create one durable window), `TestOwnerActivationAndReplay`, `TestPostgresAmbiguousActivationCommit` | None |
| P07 | Opt-in | `TestLegacyPublicIDMigrationPreservesCredentialsAndLifecycle`, `TestMigrationV1UpgradeAndRollback`, `TestImportPreservesCatalogAndHistory`, `TestImportResumesWithoutDuplicates`, `TestImportRefusesUnsafeOrChangedSources`, `TestVerificationDetectsTampering`, `TestAbortBeforeCutoverRestoresFileGateway`, `TestMarkerBelongsToItsDatabase` | Not yet run on live data |
| P08 | Partial | `TestPostgresSnapshotRestartLocksExecution`, `TestOwnerFlowsOnPostgresCatalog/loss-and-rollback`, `TestRollbackResumesAndRefusesReplacedFiles`, `TestMarkerGatesTheFileBackend`, `TestMarkerBelongsToItsDatabase` | Database backup/restore drill (step 9) |
| P09 | Opt-in | `TestOwnerRoutesFailClosedOnDatabaseLoss` (terminated executor session locks owner routes; restart suspends the old window), `TestPostgresExclusiveExecutorAndLoss` | Guarded execution at startup (step 4) |
| P10 | Library | `TestPostgresDurabilityIsolationAndPrivileges` | Retention role and procedure |
| P11 | Partial | `TestBudgetAdmissionAtomicAndConcurrency`, `TestPostgresAtomicBudget` | High-concurrency load tests (step 10) |
| P12 | Opt-in | `TestOwnerConfirmModeAndPolicyChange`, `TestOwnerVaultCredentialLifecycleAndRestart` (owner policy and credential writes go through the coordinator), `TestOwnerMutationExpiryRollsBackWritesAndRevocation`, `TestSessionRevocationWaitsForOwnerCommitAndPublication`, `TestAtomicVaultCommitFailureDoesNotPublish`, `TestAtomicVaultMutationRevokesOnlyAfterCommit`, `TestRepositoryCommitsAtomicallyAndFailsClosed`, `TestOwnerFlowsOnPostgresCatalog` (all catalog mutations commit with their event and publish after commit) | File-catalog mode still guards only key and session changes |

## 22.6 Optional-mode acceptance cases

| ID | Status | Evidence | Remaining gap |
|---|---|---|---|
| O01 | Opt-in | `TestOwnerActivationReplayAndOwnerIsolation`, `TestOwnerActivationAndReplay`; browser flow "none mode" (Start access releases the key with no confirmation dialog) | Guarded execution at startup (step 4) |
| O02 | Opt-in | `TestOwnerConfirmModeAndPolicyChange` (confirm and deny routes), `TestOwnerActivationAndReplay`; browser flow "confirm mode" (request review in the console, begin, then activate) | Guarded execution at startup (step 4) |
| O03 | Unselected | Not applicable | TOTP and push are unselected |
| O04 | Opt-in | `TestOwnerActivationReplayAndOwnerIsolation` (`none`), `TestOwnerConfirmModeAndPolicyChange` (`confirm`), `TestOwnerActivationAndReplay`, `TestEncryptedDispatchThroughMCPAndPostgres` | Factor modes are unselected |
| O05 | Unselected | Not applicable | Push is unselected |
| O06 | Unselected | Not applicable | Push is unselected |
| O07 | Opt-in | `TestOwnerConfirmModeAndPolicyChange` (revision CAS and current password), `TestOwnerRoutesRequireInteractiveBrowserSession` (keys cannot change the policy); browser flow "approval policy" (wrong password and stale revision refused) | None |
| O08 | Opt-in | `TestOwnerConfirmModeAndPolicyChange` (the change commits with stale pending requests and revoked windows, audited together), `TestOwnerFlowsOnPostgresCatalog/provider-changes` and `TestProviderChangesMoveTheSecurityRevision` (disabling a provider or hiding tools ends that connector's windows and requests and moves its revision; repeats change nothing) | None |
| O09 | Unselected | Not applicable | TOTP is unselected |
| O10 | Unselected | Not applicable | Push and TOTP are unselected |
| O11 | Opt-in | `TestOwnerActivationReplayAndOwnerIsolation` (another owner cannot read, request against, confirm, deny, activate or revoke; a substituted challenge is refused) | None |
| O12 | Partial | `TestPostgresSnapshotRestartLocksExecution` (restart locked); no push or OTP configuration exists | Cold restart through the real startup path (step 4) |
