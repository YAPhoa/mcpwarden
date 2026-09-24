# Progress

## 2026-09-24 — PR #5 review fixes

Fixed three owner-console findings from review. Each operation now captures its
generation and vault worker before its first await, so leaving `/vault` during a
recovery-key check can no longer unlock the vault in the background. A cancelled
setup no longer restores its recovery material, because results are published
only after the generation check. Locking now restores every operation's submit
control, so an interrupted unlock or setup can be retried without reloading.
Renewal compares the new request's caller, credential version, tool definition
digests, constraints, duration and call limit with what the dialog showed. If
any of them changed, it shows the new request and releases no key until the
owner allows it again.

A follow-up review found that Cancel did not stop a pending renewal or unlock.
Flows with a Cancel control now run as an operation that Cancel, closing the
dialog (including Escape), a browser lock or sign-out ends; each continuation
rechecks it after every await. A cancelled renewal sends no approval or key, a
cancelled unlock terminates its worker and leaves the vault locked, and a
cancelled credential save uploads nothing. Once an activation or credential
upload has been sent, its outcome is still reported.

A third review found that a credential save cancelled after its upload was sent
still closed the shared dialog when its response arrived, discarding a newer
form the owner had opened and started typing into. A late outcome is now reported
on the page only, and only the operation that still owns the dialog closes it,
clears it or shows field errors. While testing the late failure, its page error
disappeared as soon as the reload it queued succeeded; the same happened to other
page errors that queue a reload, such as a vanished request or an existing vault
found during setup. A refresh now clears only its own "Could not refresh" error,
and a new notice replaces an earlier error.

The owner flows now have 31 steps. The new ones hold the page's Web Crypto
digests or the wrapper read to cover leaving during a recovery unlock, retrying
an interrupted passphrase unlock, cancelling setup mid-way, and a tool
definition that changes while the renewal dialog is open. Each new check was
confirmed to fail when its fix is reverted, including renewal Cancel, renewal
Escape and unlock Cancel with the request held. The newest step holds a credential
save's response after the gateway accepted or refused it, cancels, opens a new
form and types into it, then releases the response: the form stays open,
unchanged and usable, and the outcome is reported on the page. A new unit test
covers the reviewed scope comparison.

Two stalled runs, the first CI stall and one of four parallel local runs, both
stopped at the first `page.route` on the owner's page, with no request issued and
the gateway idle. Enabling request interception later sends untimed protocol
calls to every session, including vault workers. The flows now enable
interception once when each page is created, before any worker exists.

Local validation: `gofmt`, `go build ./...`, `go vet ./...` and
`go test -race -count=1 ./...` with the PostgreSQL fixture passed, as did 55 UI
unit tests, the integrity check (18 files) and all 31 Chromium flow steps. The
late-save step failed as expected with either fix reverted: a late success
closed the newer form, and the refresh erased the late failure.
Firefox and WebKit run in CI.

## 2026-09-24 — Vault and access-window console (roadmap step 2)

Added the owner console at `/vault`, `/vault/credentials` and `/vault/settings`
for gateways with the opt-in owner API. It covers vault setup with a separate
passphrase and a recovery key that must be typed back and proven before upload,
plus passphrase or recovery unlock and passphrase changes. Owners can enter and
replace browser-encrypted header credentials for existing HTTP connectors.
Requests are reviewed with the exact caller, handle, credential, destination,
tools, constraints, duration and limits. Owners start access explicitly in both
`confirm` and `none` modes and can renew. Windows show fixed countdowns, exact
end times, call counts and filters. "Lock browser", "Stop access" and "Lock all
execution" stay separate. Live providers, their legacy headers and tool execution
are unchanged. No deployment or live configuration change was made in this
slice, and `owner_security` stays off in production.

Two additive reads support it: wrapper listings now return each live credential's
current envelope, and `GET /api/leases?include=ended` returns windows ended in the
last 24 hours. `TestOwnerLeaseHistoryAndWrapperEnvelopes` covers both, including
key and owner isolation and restart. `TestDestinationDigestVectorsSharedWithUI`
pins the browser's destination digest to the gateway's.

`ui/tests/owner-flows.mjs` runs 25 steps in a real browser against a built
gateway, a scratch PostgreSQL database, a synthetic MCP upstream and a static UI
proxy. It covers:

- setup errors and recovery confirmation, including a wrong account password
- credential encryption, a replacement conflict from a second tab, and a
  passphrase change
- untrusted labels and tool descriptions rendered as text
- explicit activation headers and body, `none` mode and renewal
- uncertain activation handled by checking status or retrying with the same key
- locking while an activation is in flight
- a 20-second window expiring, a gateway restart, and an expired session
- idle, navigation and sign-out locks that keep windows running
- another account's isolation and the disabled, untrusted and unavailable states
- responsive widths, focus return and CSP violations
- a scan of every request body, gateway log and browser storage for vault
  material

Running the flows found and fixed four bugs: a load that a lock discarded could
leave the page unable to refresh, stale lists stayed rendered after sign-out,
focus was lost after lock-all and dialog closes, and sub-minute durations were
labelled "0 minutes".

Local validation: `gofmt`, `go build ./...`, `go vet ./...` and
`go test -race -count=1 ./...` passed with the isolated PostgreSQL fixture
(PostgreSQL 16 locally; CI uses 18.6). `npm --prefix ui test` passed 54 tests, and
`python3 scripts/ci/integrity.py` verified all 18 files. The worker check and all
25 owner-flow steps passed in Chromium 141. Firefox and WebKit could not be
downloaded in this environment, so those two engines run only in CI, which now
starts PostgreSQL and Go in each browser job and runs the flows.

[PR CI run 35903731538](https://github.com/YAPhoa/mcpwarden/actions/runs/35903731538)
passed the flows in Chromium, Firefox and WebKit. An earlier WebKit run lost
keyboard focus when a background reload redrew a list; the console now restores
focus to the matching control. One earlier Chromium run stalled without an error
at the uncertain-activation step and did not recur in four local runs or the next
CI run (see the PR #5 review fixes entry above for the likely cause). The flow script now bounds its request-budget wait, times out gateway
calls after 30 seconds, and prints timestamped requests and a gateway goroutine
dump if a step stalls, so a recurrence will show its cause.

Remaining gaps: nginx sends no CSP for the main page; no screen-reader, 200% zoom
or real-device review was done; the console has no credential deletion; and
windows still do not govern ordinary tool calls until guarded startup (step 4).
## 2026-09-24 — PR #6 merge and deployment

Merged [PR #6](https://github.com/YAPhoa/mcpwarden/pull/6) at `266b329` and
deleted its feature branch. The deployed UI has searchable connector tools,
visibility filters, scoped bulk actions, expandable rows and retry controls.
Review fixes preserve policy-blocked choices during bulk changes and retain the
original requested visibility when retrying a failed save.

The merged runtime source matches reviewed head `c7e511b`. Both the
[PR CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35999110481) and
[post-merge CI](https://github.com/YAPhoa/mcpwarden/actions/runs/36001785180) passed
`go build ./...`, `go vet ./...`, the full PostgreSQL-enabled race suite,
Chromium/Firefox/WebKit, container smoke and security checks. Local UI tests and
independent Chromium regressions passed for blocked choices and stale retries;
the browser checks also found no page errors or mobile horizontal overflow.
CodeQL remained skipped for this private repository.

Redeployed the UI after a consistent stopped-gateway backup at
`/tmp/mcpwarden-predeploy-20260924-tool-visibility-1/`; keys are stored separately
at `/tmp/mcpwarden-predeploy-keys-20260924-tool-visibility-1/`. Backup directories
are mode 0700 and files mode 0600; hashes were rechecked after deployment.
UI image `533f127ca59b` runs in a new container. The gateway resumed in its
existing container with image `2a9cd8050e77`; both have zero restarts.

Live health, authorization/access/history boundaries, no-store, worker MIME/CSP,
UI source bytes and all 12 branding/favicon assets passed verification. The
encrypted account/provider catalog and audit history are unchanged byte-for-byte.
Deployment keys and gateway mounts were preserved. Live `owner_security` remains
disabled, and credential custody remains server managed. PR #5 was not merged.

## 2026-09-24 — Documentation and nginx PRs resolved

Merged [PR #4](https://github.com/YAPhoa/mcpwarden/pull/4) at `7eda80f` and
[PR #1](https://github.com/YAPhoa/mcpwarden/pull/1) at `7b2fc8b`, then deleted
their remote branches. The README now links to focused guides, and the separate
UI container uses `nginx:1.29-alpine`. PR #5 remains open for its review fixes.

Both PRs had passing required checks. The combined source tree passed the local
disposable container smoke test, including health, API authentication/cache
boundaries, served assets, and worker MIME/CSP. The merged commit's
[CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35945441420) passed
`go build ./...`, `go vet ./...`, the full PostgreSQL-enabled race suite, all
three browser jobs, container smoke, and security checks. CodeQL remained
skipped. No local test suite was repeated for the documentation-only change.

Redeployed only the UI after a consistent stopped-gateway backup at
`/tmp/mcpwarden-predeploy-20260924-nginx-1/`, with keys stored separately at
`/tmp/mcpwarden-predeploy-keys-20260924-nginx-1/`. Backup directories are mode
0700 and files mode 0600; recorded hashes were rechecked after deployment. The
gateway resumed in its existing container with image `2a9cd8050e77`. The new UI
container runs image `616239d4a5dd` and nginx 1.29.8; both have zero restarts.

Live health, authentication/access/history boundaries, no-store, worker MIME/CSP,
served UI bytes and all 12 branding/favicon assets passed verification. The
encrypted account/provider catalog and audit history are unchanged byte-for-byte.
Deployment keys and gateway mounts were preserved. Live `owner_security` remains
disabled, and credential custody remains server managed.

## 2026-09-24 — PR #3 merge and deployment

Merged [PR #3](https://github.com/YAPhoa/mcpwarden/pull/3) at `c0203dc`, with
the same source tree as reviewed head `6dd7884`. The
[PR CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35885414590) and
[post-merge CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35887537633)
passed all mandatory Go/PostgreSQL, Chromium/Firefox/WebKit, container and
security jobs. CodeQL remained skipped for the private repository. Local
build/vet/race and integrity results are recorded below.

Rebuilt and redeployed the separate gateway and UI after a consistent
stopped-gateway backup at `/tmp/mcpwarden-predeploy-20260924-owner-api-1/`;
keys are separate at `/tmp/mcpwarden-predeploy-keys-20260924-owner-api-1/`.
Backup directories are mode 0700 and files mode 0600; recorded file hashes were
rechecked after deployment. Gateway image `2a9cd8050e77` and UI image
`b7e14c305b6d` are healthy in new containers with zero restarts. Health,
authentication/access/history boundaries, history filters, no-store, served UI
source bytes and all 12 branding/favicon assets passed verification.

The encrypted account/provider catalog and prior audit history are unchanged
byte-for-byte, with no added audit records. Deployment keys and volume mounts
were preserved. The live configuration still leaves `owner_security` unset:
the new routes return 404 on both ports, and tool execution continues under
legacy server-managed custody. The next implementation slice is the vault and
lease UI; PostgreSQL catalog migration and guarded startup remain pending.

## 2026-09-23 — Owner security API review fixes

Fixed the two blockers found while reviewing PR #3. Every owner-security route
now checks actual TLS or an explicitly trusted immediate proxy before reading
authentication or request bodies. An HTTPS Origin and forged forwarding headers
cannot authorize plaintext activation. Direct loopback HTTP is a separate,
disabled-by-default development option; the examples and deployment requirements
are documented in [owner API](security/owner-api.md).

Owner policy, root and credential mutations recheck the browser session after
acquiring the database owner lock and after writes. Logout, login replacement,
explicit session revocation and password changes share the owner gate through
commit and cache publication. Fresh password checks are bound to the exact
stored verifier and rechecked under that gate. Browser revocation still preserves
approved agent windows and remains available during PostgreSQL failure.

Validation passed: `go build ./...`, `go vet ./...`, and
`go test -race -count=1 -timeout=10m ./...` with the isolated PostgreSQL fixture
enabled. New regressions cover forged HTTPS headers without reading the CEK body,
trusted proxies, direct loopback restrictions, revoked sessions during uploads
for all six mutation paths, session replacement, password changes, expiry while
waiting for the database lock, rollback on expiry during writes, and revocation
ordering through commit/publication. All 18 original spec/vendor integrity
checks passed. Hosted CI and deployment are recorded in the entry above.

## 2026-09-23 — Owner security API (roadmap step 1)

Added owner-scoped vault, credential, access-request, confirmation, activation,
revocation, execution-lock, approval-policy and audit-event routes, registered
only when `owner_security` is configured in accounts mode. PostgreSQL schema v3
adds approval policies and owner-route event types. API-key revocation now goes
through the lease coordinator. No deployment, live configuration or data change
was made; the feature is off unless configured. See
`docs/security/owner-api.md`; the acceptance matrix now lists 11 cases as Opt-in.

Validation: `go build ./...`, `go vet ./...`, gofmt and
`go test -race ./...` passed with `MCPWARDEN_TEST_DATABASE_URL` set to the local
PostgreSQL fixture, including the seven new route tests
(`cmd/mcpwarden/security_test.go`) and the existing lease/vault PostgreSQL tests
on schema v3. The owner route tests also passed four consecutive race runs.

## 2026-09-22 — Redeploy security caller/audit foundation

Rebuilt and restarted the separate Compose gateway and UI services at the user's
request. Both containers run the new images with zero restarts, retaining the
existing data volume, encryption key and operator token. UI asset version is
`20260922-security-1`.

Stopped the gateway before taking a consistent catalog/audit snapshot. Protected
data/configuration backup and SHA-256 manifest:
`/tmp/mcpwarden-predeploy-20260922-security-1/`. Deployment keys are saved separately
under `/tmp/mcpwarden-predeploy-keys-20260922-security-1/`; directories are mode 0700
and backup files mode 0600. Verified that the deployed audit log retains every byte
of the predeployment history.

Validation: Docker builds passed; `/healthz` returned 200; UI pages and all static
assets matched the source byte-for-byte. Direct gateway and UI-proxied checks passed
for sign-in options, protected-route 401 responses, authenticated status/access/
history reads, public-ID validation for returned API keys, unknown-outcome and
caller filters, and `Cache-Control: no-store`. Go build/vet/race and JavaScript
checks passed before deployment as recorded below. Smoke checks exercised
management reads; tool execution was covered by the preceding automated tests.
One GitHub connector reports an OAuth setup warning; the user confirmed it has
not been configured yet and requires no deployment action.

## 2026-09-22 — Security spec v1.1: baseline and caller/audit foundation

Reviewed the supplied v1.1 design against the actual repository, storage/history
contracts and pinned MCP SDK v1.8.0. Preserved the original bundle under
`docs/security/spec-v1.1/` and verified all 16 supplied SHA-256 entries. Recorded
the accepted threat model, supported initial owner-flow direction, implementation
gaps and remaining milestones in `docs/security/implementation.md`. A protected
67-file source baseline archive was created before edits at
`/tmp/mcpwarden-security-baseline-20260922T141536Z/`; no live data or deployment
secret backup was made and no Git commit was created.

New named keys have independent public IDs and strictly parsed `mcpw_` tokens;
full-token SHA-256 verification and legacy `mw_` compatibility remain. Existing
key records migrate only their public IDs, retaining verifiers, identity, role,
ownership, expiry and lifecycle. Caller labels refresh from the exact validated
record on every SDK request and historical snapshots survive renames/reconnects.
The Access UI displays collision-aware public suffixes. Cross-owner access-record
lookups now return an empty value rather than foreign metadata with a false flag.

Upstream and gateway-management MCP handlers now persist synced schema-v2
admission events before dispatch, then append completion separately. Admission
failure prevents the action; completion failure preserves the actual result and
never replays it. History pairs events into one invocation, exposes safe caller
attribution and filtering, and shows unresolved admissions as Outcome unknown
without fabricated completion/response/duration fields. Existing v0/v1 events and
argument-hash bytes remain unchanged. Audit diagnostics omit raw errors and both
access/history endpoints return no-store. Stdout audit configuration is now rejected
because it cannot authorize durable dispatch; the Compose file-backed default works.

Validation on Go 1.27.1: `go build ./...`, `go vet ./...`, and `go test -race ./...`
passed after the final code change. `node --check ui/static/app.js` and
`node --test ui/tests/*.test.cjs` passed, including public-handle collision and
unknown-outcome/label-escaping checks. Regression tests cover new/legacy key auth,
migration and uniqueness, owner isolation, caller spoofing, renames/reconnects,
admission and completion outages, management-action blocking, history import order,
legacy preservation, and missing-completion API metadata. Whitespace checks passed.

This completes M0 and the caller/audit portion of M1, not the full security release.
No timed lease, owner activation API, browser vault, PostgreSQL adapter, push/TOTP,
or credential conversion is implemented in this slice. No dependencies were added.
The live Compose deployment was not rebuilt or restarted. Rendered browser QA,
deployment smoke, PostgreSQL, recovery and full lease/crypto acceptance remain for
their respective milestones; the standalone reference fixture is not an application
crypto implementation. Next is the owner coordinator plus immutable timed-lease
scope/state and admission/revocation integration.

## 2026-09-22 — Append-only history portability

Added versioned events with persistent event IDs, completion timestamps and stable
upstream IDs. Proxy and runtime now depend on append/query interfaces. History uses
completion/event-ID ordering independent of ingestion order, with bounded page
selection; legacy rows receive deterministic read-time identities without disk
rewrites. History API exposes safe event/completion/provider metadata. File writes
sync before success, short/failed writes stop subsequent appends, malformed or unknown
history fails explicitly, and startup rejects incomplete final lines. Management-tool
audit failures are logged consistently with proxy failures. Documented migration,
deduplication, owner isolation and durability constraints in history-storage.md.

Validation: `go build ./...`, `go vet ./...`, and `go test -race ./...` passed.
Tests cover legacy preservation, stable IDs across reopen, timestamp and tie-breaker
ordering, pagination, provider identity, corrupt/future records and short writes,
alongside existing owner isolation, concurrent append and proxy integration checks.

## M0 — Skeleton

Go module, layout, YAML loading and validation, structured logging, and `/healthz` are implemented. Config tests pass.

## M1 — Single stdio upstream

The SDK `CommandTransport` starts a child, lists its tools, and routes namespaced calls. The curl smoke test completed initialize, initialized, list, and call against an SDK stdio mock.

## M2 — Multiple upstreams and HTTP

Startup connects concurrently. HTTP upstreams recover from startup failure and from a disconnect. `/readyz` reports per-upstream status. Race tests pass.

## M3 — Dynamic tools

The upstream list-change handler re-lists tools and the SDK downstream server emits list-change notifications. The integration test checks a live tool addition and notification.

## M4 — Policy, approval, audit

List-time policy filtering, call-time denial, `None` approval, and concurrent JSONL audit are implemented. Unit and integration tests pass.

## M5 — Hardening and packaging

Origin validation, constant-time operator bearer checks, graceful HTTP shutdown, stdio child cleanup, a Dockerfile, separate Compose admin UI, README, and smoke script are implemented. OAuth resource-server mode for ChatGPT was added at the user's request and tested with a mock introspection provider.

Validation: `go build ./...`, `go vet ./...`, and `go test -race ./...` passed. Both Compose images built. A temporary Compose run confirmed gateway health, UI delivery, and authenticated admin API proxying; its containers were stopped after verification. No Git commit has been made.

## Personal upstreams and stored discovery

The admin panel can add and remove a user's remote Streamable HTTP upstream with private headers. The gateway starts and stops those upstreams dynamically, stores their definitions and last successful `tools/list` in an encrypted file, and restores cached tool metadata for offline inspection after restart. The panel can inspect schemas, refresh discovery, and filter by provider. The API exposes provider listing and provider-specific tool search. In OAuth mode, the validated token subject isolates user registrations and `mcp:manage` gates the admin API. A two-user SDK integration test checks separate headers and tool inventories, refresh, search, and persistence. `go build ./...`, `go vet ./...`, and `go test -race ./...` passed after this change. Compose server and UI are running for the local preview. No Git commit has been made.

The first open browser tab kept an older JavaScript file after the UI was rebuilt, leaving the new Add button without its click handler. The UI now serves its HTML, JavaScript, and CSS with `Cache-Control: no-store`, and the HTML requests versioned asset URLs. Live Compose API checks confirmed add, list, and remove through the UI proxy; the saved header value was absent from list responses. An already open tab needs one reload to acquire the updated script.

## Per-user tool visibility

The admin panel now supports all-tools and selected-tools modes per provider, with a checkbox for each discovered tool. Selected mode begins with no tools visible; users can enable the few they want. Hidden tools remain in the admin inventory, disappear from downstream `tools/list`, and return an audited tool error on direct calls. Settings are encrypted with the other per-user data and survive restarts. The SDK integration test verifies user isolation, downstream list-change notification, call denial, and persistence. `go build ./...`, `go vet ./...`, and `go test -race ./...` pass. No Git commit has been made.

## Security console UI direction — 2026-09-21

Applied the supplied Style B recipe to the existing static frontend: labeled sidebar, upstream list/detail layout, separate discovery and saved-header sections, remote registration form, named removal confirmation, and tool directory. Kept the Go gateway and UI services separate. Replaced persistent token storage with page memory, suppressed raw upstream diagnostics, distinguished failed/cached/never-discovered/zero-tool states, and retained inventory with disabled mutations on transient read failure. Missing header-edit and caller-context API capabilities are documented in `ui/DESIGN.md`.

Validation: JavaScript syntax check and 8 synthetic controller tests passed; `go build ./...`, `go vet ./...`, and `go test -race ./...` passed. Palette contrast was calculated, including stronger input/button borders. The local Compose UI image was rebuilt. Browser discovery returned no available browsers: screenshots, rendered responsive/zoom inspection, real keyboard interaction, network/storage inspection, and browser accessibility checks remain unverified. No Git commit made.

Final preview verification: `http://127.0.0.1:8788` serves HTML, CSS, and JavaScript byte-for-byte matching the edited sources, each with HTTP 200 and `Cache-Control: no-store`.


## Personal accounts and separate UI screens — 2026-09-21

At the user's request, added real basic registration/sign-in using the existing encrypted catalog, salted password hashes, HttpOnly browser sessions, sign-out, and per-account MCP tokens with replacement/revocation. The authenticated status API now reports the server-validated account identity. The shared operator workspace remains accessible through the legacy token path. Basic account mode is enabled in the local preview and Compose example; registration can be closed in configuration. Accounts and external OAuth are mutually exclusive.

Replaced same-page anchors with separate upstream overview, connection detail, all-tools and per-upstream tool routes. Added personal/shared workspace labels, login/registration entry screens, and client connection dialog. Existing schemas, headers, visibility semantics, and config-managed boundaries are preserved.

Checks passed: JavaScript syntax, 11 UI controller tests, `go build ./...`, `go vet ./...`, `go test -race ./...`. New backend tests exercise account isolation, session rotation/logout/expiry, credential persistence, CSRF/origin rejection, registration closure, operator compatibility, and client token revocation. Tests needing loopback binding were rerun successfully outside the sandbox. Browser runtime still returns no browsers; Playwright MCP installed by another agent is absent from this session's callable tools. Visual/responsive/keyboard checks remain pending a new session with Playwright.

Final live checks: both Compose services rebuilt and started; HTML/JS/CSS at `http://127.0.0.1:8788` match final source bytes. `/api/auth/options` reports account mode with registration enabled; unauthenticated `/api/status` returns 401. No real or synthetic accounts were created in the live catalog during verification.

## Rendered browser review — 2026-09-21

Playwright Firefox is now available. Reviewed live sign-in and exercised synthetic accounts against an isolated gateway/mock upstream. Registration/login, account separation, connection creation/discovery, persistent tool visibility, schema dialogs, route navigation/Back, named removal/cancel, focus restoration, and personal client-token generation worked. Inspected 1440/1024/390px screenshots. Fixed initial sign-in error styling, invalid Firefox HTML patterns, post-registration sign-out mode, and missing-provider route filtering. JS syntax, 13 controller tests and Go build/vet/race checks pass. Rebuilt the live UI. Full native zoom/screen-reader/accessibility-scan coverage remains pending; mobile header density and horizontally scrolled tool actions are remaining polish items. See `ui/DESIGN.md` for exact coverage.

## Dashboard and connector tool lists — 2026-09-21

Implemented latest screenshot feedback: dashboard landing, linked Upstreams breadcrumb, tools directly on connector pages, collapsible connection settings, 10/25/50 pagination, search toggle, discoverable/not-discoverable filters, and per-tool switches. Mobile rows keep switches visible. Discoverability follows gateway allowed/healthy/visible semantics; settings remain scoped per user through existing APIs.

Validation: 16 controller tests, JS syntax, Go build/vet/race checks passed. Playwright Firefox verified the real flows in an isolated gateway with 71 synthetic tools, including pagination, search, both filters, visibility mutation, breadcrumb return and dashboard count changes. Inspected 1440px and 390px screenshots. No test accounts or tool changes were added to the live workspace. UI service rebuilt for the preview.


## UUIDs, provider controls, and upstream authentication — 2026-09-21

Completed the user's request for original tool labels and UUID internal registry/UI keys while retaining existing MCP wire names and visibility rules. Encrypted connector records migrate to persistent UUIDs. Added a per-user provider switch that stops the connection and blocks tools without losing cached inventory, credentials, or selections.

Expanded upstream registration to no auth, bearer token, API-key header, custom headers, and generic MCP OAuth. OAuth uses the pinned SDK with preregistration or dynamic registration, explicit browser consent, PKCE, browser-bound one-time callbacks, encrypted grants and persisted token refresh. Connect/reconnect is visible at the top of the connector page. The user has not selected a Google Drive MCP server; no Google-specific adapter or real Google account integration was tested.

Validation: Go build/vet/race checks and 19 controller tests passed. Backend tests cover legacy migration, identity stability, disabled-provider restart, per-user isolation, direct-call blocking, unchanged wire names, SDK OAuth preregistration and DCR, PKCE/resource parameters, wrong-browser and replay rejection, encrypted grant restoration and refresh-token rotation. Firefox exercised short labels/schema details, UUID stability, retained manual choices after disable/enable, and a full mock OAuth consent popup through discovery. Desktop 1440px and mobile 390px screens were inspected; the connector and registration dialog had no horizontal overflow. All accounts and credentials used for browser testing were synthetic in a separate temporary store.

Deployment: rebuilt and restarted both local Compose services. The live panel at `http://127.0.0.1:8788/` serves the updated authentication choices and versioned UI assets; auth options respond successfully in account mode. Existing browser sessions need sign-in after the gateway restart. The isolated browser test gateway was stopped and its temporary encrypted store cleaned up.


## Provider actions on overview pages — 2026-09-21

Reviewed the user's 12:36 screenshot of the upstreams list. Added refresh and enable/disable controls directly to upstream rows and dashboard connection rows, using separate links and controls so actions do not navigate. Moved connector refresh above the tool list. Disabled providers cannot refresh; pending operations disable conflicting actions and restore focus on completion.

Validation: 19 existing UI controller tests, JS syntax, Go build/vet/race checks pass. Firefox exercised refresh and disable/enable from the upstreams list, refresh/disable from the dashboard, retained routes, and visibility of the detail refresh button. Inspected desktop/mobile screenshots and measured no horizontal overflow at 390px. Rebuilt only the UI service; gateway sessions remain intact.


## Connector toolbar refinement — 2026-09-21

Applied the 12:42 screenshot feedback: permanently visible search field with adjacent discoverability/provider filters, consistent heading-action alignment, and a prominent plain Refresh button. Removed the upstream column from connector-scoped tables; the all-tools directory retains it. Search remains scoped per connector and filters/pagination still work.

Checked Firefox at 1440px and 390px, searched a 71-tool fixture, verified single-connector column removal and all-tools column retention, and measured no mobile overflow. JS syntax, 19 controller tests, and Go build/vet/race checks pass. Rebuilt only the UI service.


## 2026-09-21 — Admin/client access and stable provider controls

Implemented distinct admin/client MCP views, admin management tools, client per-provider refresh, and owner/credential/role-bound sessions. Added encrypted named API keys, persistent browser sessions, observed OAuth sessions, live MCP connection tracking, expiry, rename/revoke, lifecycle timestamps, legacy token migration to client role, and hard per-workspace limits of 10 active keys, 10 browser/OAuth sessions combined, and 10 MCP connections. Access page replaces the topbar client setup action and shows device/client names, activity, expiry, current session, and history.

Upstreams now shows provider enabled/disabled/total counts and saved tool-choice totals per connector. Bulk Enable all tools/Disable all tools applies across filters and pagination. Fixed the switch twitch by locking existing controls in place during saves instead of rendering the old checked state; stabilized provider switch labels and widths.

Validation: Go build, vet, and race tests passed, including real HTTP/SDK role isolation, client refresh, cross-key session rejection, session/key revocation, and rejection of an eleventh MCP connection. Catalog tests cover atomic key caps, shared browser/OAuth caps, expiry, persistence/migration, and revoked OAuth tokens. All 23 JavaScript controller cases passed. Isolated Firefox checks verified key creation/role restriction, rename/revoke, current-session sign-out, desktop/mobile layout, and bulk changes over 71 tools. A delayed visibility PUT preserved the same DOM switch and identical bounding box with the new checked state. Mobile upstream page had no horizontal overflow. No live upstream settings were changed in these checks.

The saved-header screenshot confirms a separate missing edit feature: non-OAuth credentials can safely be replaced without revealing existing values; OAuth authorization should use reconnect. This was explained to the user; credential editing remains unimplemented.

Rebuilt and restarted both Compose services. Live panel serves asset version 20260921-12 and the account authentication endpoint returns HTTP 200. Existing pre-migration browser sessions require a fresh sign-in after this restart.

## 2026-09-21 — Explicit connector buttons

Reviewed the latest header screenshot and replaced connector switches with fixed-width red Disable connector / green Enable connector buttons on detail, upstream list, and overview. Refresh follows the connector action on the right. Removed the intermediate successful refresh render during connector saves. Bulk action scope help is collapsed behind a keyboard-accessible “i” disclosure. Confirmed registration/storage do not enforce a numeric upstream count limit.

Validation: JavaScript controller checks and Go build/vet/race passed. Firefox verified detail disable/re-enable, list disable, identical button position and size throughout a delayed save, refresh placement, info disclosure, and no overflow at 390px. Rebuild UI only; gateway and existing sessions are unaffected.

## 2026-09-21 — Compact multi-upstream tool filter

The latest screenshot referred to the Tool directory filter. Replaced its single select with a checkbox menu supporting several upstreams, selection-count label, Show all reset, outside-click/Escape dismissal, and URL-preserved selections. Search, discoverability, and pagination apply to the combined inventory. Connector detail remains scoped to one upstream. Changed the bulk-action “i” disclosure to a hover/focus tooltip and reduced toolbar and connector action sizes.

Validation: controller checks, Go build/vet/race passed. Firefox selected two of three synthetic upstreams and showed exactly 142 tools; verified tooltip hidden/hover/re-hide/focus behavior and no overflow with the menu open at 390px. Deploy UI only.

## 2026-09-21 — Connector state and tool visibility

Restored connector switches in upstream/overview lists and shortened detail buttons to Enable / Disable. Clarified independent tool choices and explicit connector AND tool gating in the UI. Backend already preserves visibility selections when pausing connectors. Firefox verified a 71-tool connector with one hidden tool: disabling produced zero discoverable tools while all saved choices stayed identical; enabling through the list restored the same 70 enabled choices. JS controller checks and Go build/vet/race passed. UI-only deployment.

## 2026-09-21 — Independent tool discovery display

Reviewed the screenshot showing “Not discoverable / Provider disabled.” Tool-table badges, counts, and filters now reflect saved visibility plus policy independently of connector state/health. Effective dashboard discovery and backend MCP enforcement still require an enabled, available connector. Updated explanatory copy. Regression check verifies identical tool-row markup before and after connector disable while effective dashboard count becomes zero. Controller tests and Go build/vet/race passed. UI-only deployment.

## 2026-09-21 — Bulk visibility blinking

Bulk visibility previously dimmed all mutation controls, loaded four inventory endpoints, and rendered twice. It now applies the authoritative visibility response to local tool/provider state, updates only tool rows/counts and the visibility selector, and locks relevant controls without opacity changes. No full inventory reload or page render. Identity-epoch checks guard stale completion. Controller regression verifies one save request per action and updated counts. Firefox toggled all 71 fixture tools in both directions; mutation observation found no changes to Refresh/connector controls or replacement of connection settings (only expected visibility-selector lock attributes). Go build/vet/race and controller tests passed. UI-only deployment.

## 2026-09-21 — Stable reload, reconnect refresh, and appearance

Reload inventory keeps its label/opacity stable and skips rendering unchanged snapshots. Refresh now waits (up to 30 seconds, respecting cancellation) for a newly enabled connector's initial connection/discovery attempt, rejecting disabled or replaced generations. Previously the asynchronous enable path could return before a session existed and an immediate refresh returned 503. Added a slow HTTP upstream regression covering three enable/immediate-refresh/disable cycles.

Added persisted Light/Dark/System appearance controls on sign-in and workspace pages, applied before rendering to avoid a theme flash. System mode follows OS changes; menus, tooltips, and action colors adapt to light mode. Go vet/build and race tests plus JS controller tests passed. Firefox verified three rapid cycles returned HTTP 200, unchanged reload retained the same row DOM node, theme persistence after reload, system light/dark changes, and no horizontal overflow at 390px. Visually reviewed light desktop UI. Both services rebuilt for the backend fix.


## 2026-09-21 — Workspace history and account navigation

Added owner-scoped persistent call history using existing JSONL audit storage, stable tool IDs/name snapshots, outcome/latency/response-count/structured-response metadata, and safe paginated management API. Workspace History filters by time, status, and tool, retaining removed connector tools; each tool dialog has Details/History tabs. No payloads or raw errors are stored in history. Kept history append-only instead of introducing soft deletion or relational foreign keys; documented scan/retention limits and exclusion of ownerless legacy audit records.

Moved Refresh all to Upstreams (refreshes enabled providers, reports failures), the MCP guide to Access, and theme/sign-out/password change into an expandable bottom-left menu. Password change verifies the current secret, updates salted hashes atomically, and revokes other browser sessions. Fixed a session-cleanup shutdown race found during testing by waiting for cleanup persistence before runtime teardown.

Validation: final Go build, vet, race suite and JS controller checks passed. Tests cover real MCP call attribution and user-isolated API history, forbidden client access, safe returned fields, persistence/pagination/time/status/tool filtering, invalid filters, password verification, new/old login credentials, and session revocation. Firefox generated 27 real synthetic MCP calls, verified 25+2 pagination, tool/status/time filters, per-tool 26-call history, history retained after connector removal, password change, Refresh all, Access guide, sign-out clearing history, and mobile no-overflow. Reviewed desktop History layout. Both services rebuilt for deployment.

## 2026-09-21 — Explicit history time selection

Replaced browser-dependent datetime-local fields with date calendars plus visible 24-hour and minute dropdowns for From and Until. Retained local-time conversion and exclusive Until semantics. Firefox selected 13:45–14:30 and verified outgoing timestamps, 24 hour/60 minute options, and mobile layout. Controller checks and Go build/vet/race passed. UI-only deployment.

## 2026-09-21 — Service grouping and clear header status

History now groups each page's calls by upstream service, with a primary upstream filter and an optional tool filter scoped to that service. Backend filtering and facet metadata remain owner-scoped, including archived service names. Tool rows use short names within their service group. Authentication is a neutral Signed in/Management access indicator; a separate connector badge distinguishes no connectors, all disabled, unavailable, partial availability, and available. Moved these compact indicators to the top-right header per user feedback.

Validation: Go build/vet/race and JS controller checks passed, including upstream filtering and non-green unavailable state. Firefox generated calls across two fixture services, checked grouped results, a two-tool scoped filter, and header status placement. Hour/minute controls from the preceding change are included; mobile layout has no horizontal overflow.

## 2026-09-21 — Clear local sign-in versus advanced token access

Moved the token login alternative behind Advanced access in local account mode and labeled it Operator / OAuth token. Local authentication errors now prompt username/password sign-in. OAuth/operator-only modes keep advanced access expanded. Client API keys remain credentials for MCP apps. Controller checks and Go build/vet/race passed.

## 2026-09-21 — Minimal local login screen

Reviewed the screenshot and removed the appearance selector above the login card. Removed the advanced/token alternative entirely from local-account sign-in. Username/password and registration remain; appearance is available after login in the account menu. Operator/OAuth-only configurations retain their necessary Connect action. JS controller checks and Go build/vet/race passed. UI-only deployment.

## 2026-09-21 — Platform-wide proxy performance and malformed response isolation

Added persistent microsecond handler/upstream/gateway timing for every routed upstream call through client/admin MCP, including error/timeout/denied paths. History API returns bounded-memory aggregate counts, means, maxima and p50/p95 histogram upper bounds over all matching timed records. UI shows per-call breakdowns and filtered average/p95 summaries, preserving legacy duration-only rows and owner isolation. Documented scopes/exclusions and ongoing performance methodology in docs/proxy-performance.md.

Removed forced shared-session closure on individual CallTool errors. Added malformed-content regression proving subsequent valid calls reuse the same upstream session; real disconnect/reconnect tests still pass. Kaggle verbose pagination reproduces the upstream generic error, while simple page/pageSize works through the configured gateway. The malformed authorize response remains an upstream protocol error rather than being silently rewritten.

Validation: go build ./..., go vet ./..., go test -race ./... and all 28 JS controller checks passed. Timing tests cover success, tool errors, denial and timeout; aggregate tests cover persistence, legacy records, owner/connector isolation and pagination independence. Rebuilt and deployed gateway and UI (asset version 20260921-24).

## 2026-09-21 — Account launcher and settings styling

Applied Downloads/mcpwarden-account-settings-page-SKILL.md as visual direction, per user clarification. Bottom-left identity launcher opens a compact 280px popover with Account settings, Appearance, Security and the mode-specific exit action. Moved appearance and the existing password form into routed settings sections; kept the existing UI stack and theme tokens. Removed the duplicate sidebar identity card visually. Added responsive theme preview radios using the existing guarded browser preference, route heading focus/return context, Escape/outside dismissal, and password show/hide, discard confirmation and clear-on-completion. No backend capabilities added.

Validation: Go build/vet/race and all 28 controller checks pass. Isolated Firefox synthetic-account review covered 320/390/768/1440 viewport bounds, light/dark and System live changes, settings heading focus, Escape focus return, real existing password endpoint success and field clearing. No screen-reader or actual 200% browser zoom audit. Captured 20 offline HTML states and 40 desktop/mobile PNGs using synthetic data, packaged with CSS and review notes in Downloads/mcpwarden-ui-review-20260921.zip. Verified archive integrity and relative file links. UI asset version 20260921-25.

## 2026-09-21 — Visual critique refinement (R01–R12)

Read Downloads/CRITIQUE.md and the embedded skill/handoff from mcpwarden-visual-review.html. Applied the directions to the existing frontend, keeping current gateway contracts and dark/light tokens.

- Mobile: replaced the resting fixed account overlay with one launcher moved into an in-flow header; added an explicitly expanded navigation panel. Desktop keeps the footer identity row. Account disclosure positioning now derives from the trigger geometry and viewport bounds.
- Hierarchy: aligned compact personal settings with working content, removed redundant framing/eyebrow and unrelated discovery footer. Added Tools / Connection settings routes directly below the upstream heading; preserved tool state and restored tool scroll when returning.
- Working pages: tightened short tool rows and retained mobile labeled fields. Access now leads with existing records/quotas, discloses creation and connection guidance, and places device/timestamp details behind record disclosures. History preserves existing filters/aggregate semantics while disclosing exact time controls and definitions; rows now align time, tool, outcome and timing.
- Status/copy: hid the ambiguous global connection indicator; actual connection state and last discovery remain in the upstream context. Retained cached/failed/disabled/unknown and tool visibility semantics. Refined theme previews, selection versus focus, System resolved-scheme help, account wording and password-action labels.

Validation: Go build/vet/race and all 28 controller checks pass. Firefox tested 100 page/width/theme combinations (ten routes, 320/390/768/1024/1440 CSS pixels, light/dark), checking overflow and resting launcher positioning. Menu bounds tested at each width/theme. Verified native menu Enter/Tab/Escape and focus return, mobile navigation expansion/collapse, settings heading focus, connection tabs retaining search, actual isolated-gateway call history rendering, System live changes, and explicit theme selection when localStorage throws. Existing controller coverage includes unknown, zero-tool, stale, failed and disabled discovery states. Screenshots inspected for mobile Security and desktop Access/History. Real mobile soft keyboard, screen readers and actual 200% browser zoom were not tested. Deployed UI asset version 20260921-26.

## 2026-09-21 — Prevent login flash during session restoration

Initial HTML now hides sign-in and the workspace behind a neutral loading state. The controller retains that state through auth-mode and session/inventory checks, then shows the correct destination. Initial connection errors remain visible on the sign-in screen. No stored identity or credential is used to guess login state. Asset version 20260921-27 deployed.

Validation: 29 controller checks (including delayed startup and signed-out completion), Go build/vet/race passed. Firefox tested deployed assets with synthetic intercepted API responses and a delayed auth-options response: sign-in stayed hidden during startup, authenticated state showed the workspace directly, and a 401 showed sign-in only after checking completed.

## 2026-09-21 — History columns matching the review screenshot

Replaced combined timing rows with a semantic table: Time, Tool, Upstream provider, Status, Total time, Upstream time, Gateway time. Provider identity has its own column rather than repeated grouping headers; rows retain API chronological order and all filters/aggregates retain their existing scope. Kept response metadata, explicit Not forwarded for denied calls and Not recorded for historical timing gaps. Narrow viewports stack labeled fields. Deployed UI version 20260921-28.

Validation: 29 JS checks and Go build/vet/race passed. Firefox inspected deployed assets with synthetic success, denial and legacy rows; confirmed all seven headers, correct timing fallbacks, and no horizontal overflow at 320/390/1024/1440px. Desktop screenshot inspected against the supplied reference.

## 2026-09-21 — Missing navigation symbols

Added the five 16px outline SVG symbols from the supplied original visual proposal beside Dashboard, Upstreams, Tool directory, History and Access. Icons inherit the link color and are decorative to assistive technology; text labels and navigation semantics remain. UI version 20260921-29 deployed.

Validation: 29 JS controller checks and Go build/vet/race passed. Firefox verified all five rendered icons at 16×16 on desktop and in expanded mobile navigation, with aria-hidden, and inspected a sidebar screenshot against the user's reference.

## 2026-09-21 — App-wide UI timezone preference

Added Appearance → Timezone with automatic device timezone, UTC and browser-supported IANA zones. The non-sensitive preference is guarded browser storage, independent of account and theme. Shared timestamp formatting covers history, tool history, upstream discovery and access lifecycle dates, with 24-hour time and zone abbreviations. History shows the active zone and converts date/hour/minute bounds to UTC instants, keeping inclusive From and exclusive Until. Changing the preference invalidates old history rendering and updates other timestamp surfaces. Audit storage and authentication expiry remain unchanged.

Timezone conversion uses Intl offsets around each wall-clock boundary. Invalid dates and DST gaps/folds produce explanatory errors rather than silently choosing a different instant. No dependencies or backend changes. UI asset version 20260921-30 deployed.

Validation: 29 controller checks plus four timezone tests cover Singapore, Kathmandu, UTC, New York summer/winter, US DST gap/fold, Lord Howe half-hour gap/fold, invalid dates and missing browser storage. Go build/vet/race passed. Firefox verified preference persistence after reload, a UTC 10:30 record rendering as 18:30 SGT, an 18:30 Singapore filter transmitting 10:30Z, and no mobile overflow at 390px; inspected the Appearance screenshot.

## 2026-09-21 — Access page fidelity correction

Compared Screenshot From 2026-09-21 23-34-27.png to the proposal's actual Access markup. Corrected the earlier partial implementation: compact connection-guide banner, Create key beside its quota heading, real modal key creation, visible created/last-used/expiry summaries, quieter rename actions, separate Signed-in sessions and MCP connections with their own quotas, current-session chip and active-state marker. Exact dates/device information and access history remain available. Summary dates honor the new UI timezone. Added the proposal's refresh/plus symbols.

Creation retains the existing API, roles, expirations, cap and shown-once token flow; errors are visible inside the modal, repeated submission is blocked, and cancellation is disabled during minting. MCP record rename/revoke handlers now bind to the new dedicated list. No backend changes. Deployed asset version 20260921-31.

Validation: Go build/vet/race, 29 controller checks (quota labels updated) and four timezone checks passed. Isolated Firefox with a synthetic local account verified real API key creation, shown-once value clearing, rename, revocation with disconnect warning, updated counts, guide dialog, Escape/focus return and narrow creation dialog. Checked no overflow at 320/390/768/1440 in light/dark; inspected the desktop Access screenshot against the proposal.

## 2026-09-21 — Pagination screenshot investigated after Access deployment

Completed Access UI deployment first, as requested. Investigated Screenshot From 2026-09-21 23-38-25.png with ten read-only query variants. Correctly wrapped explicit page/pageSize and all three presence flags succeed; pageToken:null and an unwrapped argument object reproduce generic tool errors. Kept the distinction between the screenshot's summarized call and observed wire shapes; its original cause cannot be inferred from the image. Wrote docs/bugs/kaggle-pagination.md with reproduction matrix and workaround. No payload/credential logging, argument rewriting, automatic tool retries or external issue submission.

## 2026-09-22 — Date range proposal integration

Integrated Downloads/SKILL.md, CRITIQUE.md and mcpwarden-date-range.html as design direction. History now has a 960px editor with two 48px compound endpoints, native calendar dates and editable 24-hour times, inclusive/exclusive labels, selected timezone, elapsed duration, snapshot shortcuts, draft indication and Revert. Existing Apply filters remains the sole commit action. Open bounds remain supported; partial, invalid, equal/inverted and DST gap/fold boundaries are rejected without discarding input. Refresh and pagination use committed timestamps, independent of draft edits. Timezone changes reformat committed boundaries while preserving their instants. No backend or dependency changes. Asset version 20260921-32.

Validation: 31 controller checks and four timezone checks passed; Go build/vet/race passed. Firefox with an isolated synthetic account verified zero draft requests, exact Singapore-to-UTC query serialization, inline inverted-range rejection, refresh retaining applied bounds, and Revert. Rendered dark/light layouts at 320/390/768/1440px without overflow; inspected desktop dark and mobile light screenshots. Native calendar behavior is retained; screen-reader and other-browser testing was not performed.

## 2026-09-22 — Make range application discoverable

Moved the single Apply filters action below the date-range editor and gave it primary styling. Pending range text now directs users to that button; the action row explains that it applies status, upstream, tool and date range. Clear remains alongside it. Asset version 20260922-33. Existing JS checks and Go build/vet/race pass. This is a placement/copy change; query semantics are unchanged.

## 2026-09-22 — Open calendar from the whole date field

Clicking anywhere in either History date field now invokes the native showPicker API. Keyboard focus retains editable date segments; unsupported browsers retain native behavior. Calendar icon hover styling is retained/explicit for WebKit controls; Firefox retains its native icon. Deployed UI version 20260922-34. Existing JS checks and Go build/vet/race passed.

## 2026-09-22 — Proposal-style custom calendar

Replaced the native History date picker with a custom popup adapted and reviewed from the supplied original proposal. It uses app semantic theme tokens, a compact six-week grid, selected/today states, month arrows, Use today and Cancel. Today uses the app-selected timezone. Date text remains directly editable as YYYY-MM-DD; the whole field and separate hoverable icon open the popup. Selection updates the draft only and leaves time untouched. Arrow/Home/End/Page Up/Down navigation, month-end clamping, year movement, modal focus containment, Escape/outside close and trigger focus return are implemented. No dependencies or API changes. UI version 20260922-35 deployed.

Validation: existing JS controller/timezone checks and Go build/vet/race passed. Firefox verified date selection, arrow movement, January 31 → February 28, Home, Escape and focus return. Inspected dark desktop/light mobile screenshots and checked popup/grid fit at 320/390/1440px in both themes. Fixed inherited inventory-table minimum width discovered during visual review. Other browsers and screen readers remain untested.

## 2026-09-22 — Remove visible calendar keyboard hint

Made the calendar keyboard instructions screen-reader-only, retaining its accessible description while removing the visible footer text. UI asset version 20260922-36. Existing JS checks and Go build/vet/race pass.

## 2026-09-22 — Simplify calendar heading

Removed visible Choose From/Until date text, preserving it as the dialog's screen-reader label. Month/year now leads the popup. UI version 20260922-37; JS checks and Go build/vet/race pass.

## 2026-09-22 — Center calendar navigation icons

Replaced font chevrons with 18px SVG arrows centered by the existing grid buttons, removing font-baseline misalignment. UI version 20260922-38. Existing JS checks and Go build/vet/race pass.

## 2026-09-22 — Align calendar weekday headings

Weekday headings inherited left alignment from the inventory table. Explicitly centered calendar header/data cells. Firefox verified all seven heading centers coincide with date-column centers at 390px and 1440px. Existing JS checks and Go build/vet/race pass. Deployed UI version 20260922-39.

## 2026-09-22 — Search field autocomplete

Set autocomplete off, spellcheck false and autocapitalize none on tool and upstream search fields. These fields had no autocomplete restriction; reported unrelated suggestions are consistent with browser form history, though the user's browser popup was not directly observed. Hash routing remains unchanged. Existing JS checks and Go build/vet/race pass. UI version 20260922-40.

## 2026-09-22 — Clean UI URLs

Replaced hash-based navigation with History API paths, updated static/dynamic links and programmatic navigation, and retained old #/ bookmarks via replaceState migration. Nginx already provides the index fallback for direct routes; API routing remains unchanged. UI version 20260922-41 deployed.

Validation: 32 controller checks plus timezone checks and Go build/vet/race passed. Firefox synthetic workspace verified old bookmark migration, connector tabs, Back/Forward, page refresh, sidebar navigation and direct appearance-page entry with no page errors.

## 2026-09-22 — Simplify page heading hierarchy

Reviewed Screenshot From 2026-09-22 00-36-36.png. Removed redundant uppercase eyebrow labels from Dashboard, History, Upstreams, connector detail and Tool directory page headings. Kept each title and its explanatory description. Existing JS checks and Go build/vet/race pass. UI version 20260922-42.

## 2026-09-22 — Sidebar width and shared breadcrumb gutter

Reviewed Screenshot From 2026-09-22 00-37-45.png. Widened the desktop sidebar from 224px to 248px and updated the workspace offset. Topbar horizontal padding now matches the centered 1600px main-content container, fixing the breadcrumb/title offset on wide screens. Mobile shell overrides remain in effect. Deployed UI version 20260922-43.

Validation: JS controller/timezone checks and Go build/vet/race pass. Isolated Firefox preview using the actual UI assets and synthetic API fixtures checked seven routes, eight widths (320–2560px), both themes: no overflow or breadcrumb/title misalignment. Mobile navigation, account popup bounds, Back/Forward and reload passed with no page errors. Inspected the 1920px Access screenshot. Running UI container returns HTTP 200 for /access internally. Browser and host curl requests to published localhost:8788 timed out during this turn, so live end-to-end verification could not be completed; isolated checks do not establish live API health.

## 2026-09-22 — Go 1.27 and module housekeeping

Updated the module language baseline and local requirement to Go 1.27, and pinned the container build stage to Go 1.27.1, the current stable patch release. Ran `go get -u ./...` and `go mod tidy`; this updated `golang.org/x/oauth2` to v0.37.0, `github.com/segmentio/asm` to v1.2.1, `golang.org/x/sync` to v0.23.0, `golang.org/x/sys` to v0.48.0 and `golang.org/x/time` to v0.16.0. The pinned MCP SDK remains at its current v1.8.0 release.

Validation: `go mod verify`, `go build ./...`, `go vet ./...` and `go test -race ./...` passed with Go 1.27.1.

## 2026-09-22 — Backend-neutral managed-state design

Reviewed managed catalog and history persistence for alternative database compatibility. Audit/history already used `audit.Store`; managed state was coupled directly to the encrypted file `*catalog.Store`. Added the `catalog.Repository` contract and changed runtime, local-account authentication, access management, upstream OAuth, and startup wiring to depend on it. The existing encrypted file store remains the default and implements repository lifecycle closing. Added an injected-repository regression test.

Documented concurrency, owner isolation, defensive-copy, durability, transactional limit/uniqueness/OAuth-CAS, lifecycle, secret-at-rest, cached-read, and single-active-process requirements for a future PostgreSQL adapter. No driver, schema, configuration, or migration was added; a concrete adapter can now be wired without changing the business/runtime layers. Updated the README and decisions record.

Validation: `go mod tidy -diff`, `go build ./...`, `go vet ./...`, and `go test -race ./...` passed with Go 1.27.1.

## 2026-09-23 — Lease core, PostgreSQL metadata and Sonic

Continued the security v1.1 work begun on September 22, with the user's explicit
authorization for PostgreSQL testing and final choice of Sonic. Added Sonic
v1.15.4 behind `internal/jsoncodec` for catalog snapshot encoding and new
security/storage JSON. Catalog fixtures compare the actual serialized SDK tools,
IDs, verifiers and timestamps byte-for-byte with the old encoding and reopen the
encrypted file. Legacy catalog decoding and audit argument hashing retain their
existing codec. No JSON v2 experiment is needed. Local 32-tool codec benchmarks
showed about 2.1× faster encoding and 1.8× faster decoding, with more allocated
bytes; this is not a gateway throughput measurement. Strict input validation is
measured separately and remains enabled at authorization boundaries.

Added an owner-coordinated lease engine with strict bounded RFC 8785 scopes,
exact caller/epoch/boot/tool-definition binding, `none`/`confirm` owner activation,
fixed deadlines, explicit renewal, idempotent activation, request limits,
concurrency control, optional atomic call budgets, revocation, clock-discontinuity
suspension and material cleanup. An activation capability is published only after
commit; interruption/ambiguous commit clears staged material and stops execution.
Added validated lease-attribution fields to invocation audit without changing the
existing argument hash. Provider work runs outside the owner coordinator.

Added the pgx v5.11.0 lease-metadata adapter, a reviewed checksummed SQL migration,
and `cmd/mcpwarden-security-db`. A dedicated session holds executor ownership;
startup suspends prior leases, lock loss stops admissions, and owner transactions
sample the actual clock after acquiring the row lock. Runtime roles cannot mutate
audit, perform DDL, inherit the schema owner or escalate through powerful role
membership. Admission counters and audit commit together. Real PostgreSQL tests
cover role restrictions, owner isolation/FKs, immutable bindings, contention,
deferred commit rejection, a successful COMMIT with its reply deliberately lost,
executor termination, competing executor/migration, and snapshot restore locked.

Started the isolated `mcpwarden-security-test` Compose project with PostgreSQL
18.6 on `127.0.0.1:55432` and its own volume. Ran the migration CLI on the base
test database with a separate `mcpwarden_runtime_test` role. Schema version 1 is
present; no live credentials, leases or invocation data were imported. Integration
tests created and cleaned up their own scratch databases/roles. The test service
remains healthy and running for subsequent work.

Validation with Go 1.27.1:

- `go build ./...`, `go vet ./...`, and **`go test -race ./...` with PostgreSQL
  enabled** passed on the final code. PostgreSQL tests did not skip in that run.
- `go mod verify` passed; `go mod tidy -diff` produced no changes.
- `CGO_ENABLED=0 go test ./internal/jsoncodec ./internal/catalog` and a CGO-disabled
  gateway build passed. Native Sonic execution was checked on linux/amd64.
- Both existing UI test files passed via Node's test runner. No UI code changed.
- All 16 supplied security-spec hashes still match. Scope normalization has a
  fuzz target in addition to deterministic duplicate/Unicode/number/predicate tests;
  the short fuzz smoke was not a sustained fuzzing campaign.

This completes the tested foundation slice, not M1/M2 or the security release.
The lease engine is not yet wired into gateway authentication, owner routes,
credential execution or the UI. Its activators use synthetic test material.
Browser VRK/CEK lifecycle, strict credential envelopes, full catalog/history
migration, coordinated real catalog mutations, gated discovery/OAuth refresh,
SSRF/stdio hardening and rollout/recovery drills remain. The migration design and
exact boundaries are in [lease storage](security/lease-storage.md).

No production restart or credential migration was performed in this slice. The
source baseline is preserved at `/tmp/mcpwarden-security-phase2-jq3wrr_g/` (91
source files and checksums, excluding ignored runtime data and secrets). The
previously deployed gateway/UI remain on their existing file storage.

## 2026-09-23 — Real encrypted activation and guarded MCP dispatch

Continued with the next execution boundary. Added strict, bounded
`mcpwarden.secret.v1` AES-256-GCM parsing with expected-context RFC 8785 AAD and a
real `secret.Activator`. Header bundles must match the destination's approved
names. Activation consumes and clears the selected CEK, publishes only opaque
header material after the existing durable lease commit, and provides no root,
passphrase, recovery or server-unlock path. Handles reject JSON serialization,
redact diagnostics and clear owned buffers when drained. The Go runtime and HTTP
library may retain temporary copies; no guaranteed-zeroization claim is made.

Added a versioned destination profile and dedicated transport with exact endpoint
and header binding, connection-time DNS/IP checks, direct checked-IP dialing,
private-prefix limits, strict loopback-only HTTP, no environment proxy and no
redirect following. The guard rejects framing/routing/MCP/retry headers and
special-use/metadata destinations. Each request checks the original live lease
capability, including after DNS; detached SDK contexts cannot retain authority.

Added bounded pre-admission maintenance, material-aware single-use dispatch,
and an opt-in proxy adapter using the pinned SDK. Setup checks the actual selected
upstream tool definition before the transactional call budget/admission. Final
admission stays on the prepared activation. Fixed the old-material/new-revision
attribution gap and strengthened checks at transport injection. Wire arguments
use a separate number-preserving ephemeral binding; the original persisted audit
hash and RFC 8785 scope hashes are unchanged. No new dependencies were added.

Real SDK/PostgreSQL tests now use encrypted synthetic credential envelopes and
the actual activator/transport/proxy. Both `2025-11-25` and `2026-07-28` downstream
protocols execute 25 calls under one unchanged deadline, reconnect through the
admin view, and independently confirm committed database admission at the
upstream before its effect. Tests cover cached tools while locked, wrong keys,
owner-only activation, a second active API key, actual revision/caller snapshots,
lost responses without replay, completion failure preserving success, redirects,
definition drift, revocation and a real deferred admission commit rejection.

Validation on Go 1.27.1 / Node 20.19.2:

- `go build ./...` and `go vet ./...` passed.
- **`go test -race ./...` with PostgreSQL enabled passed**; the new full dispatch
  tests and existing storage/commit/restore tests ran, rather than skipped.
- The original public envelope vector passed. Go-to-Node-WebCrypto decryption
  and Node-WebCrypto-to-Go encryption passed with Unicode owner identities.
  This is primitive interoperability, not a browser vault/Argon2 test.
- A 10-second envelope fuzz run completed 286,487 executions without failure.
  This was a smoke test, not sustained security fuzzing or an external review.
- Both existing UI tests passed. No UI, config, dependency or SQL migration
  changes were needed; all 16 original spec-manifest hashes still match.

The isolated PostgreSQL 18.6 fixture remains healthy at `127.0.0.1:55432`.
Tests cleaned up their scratch databases/roles; no live data was imported.
The pre-edit source backup contains 107 files and checksums at
`/tmp/mcpwarden-security-phase3-82_pv9hx/`, excluding ignored runtime data/secrets.

This completes the tested encrypted-execution adapter slice, not the M2 release.
The application has not installed it at startup, and the production services
were not redeployed. Credentials still use the legacy encrypted file. Browser
root/CEK wrappers, vault setup/recovery, encrypted-record persistence with
CAS/nonce/cap enforcement, owner routes/UI, coordinated catalog/history migration,
initial provider setup, OAuth refresh and load/restore qualification remain.
See [encrypted runtime](security/encrypted-runtime.md) for exact contracts and
release gates, and [decisions](decisions.md) for the pinned SDK behavior review.

## 2026-09-23 — Browser vault primitives, encrypted records and redeployment

Added ciphertext-only root/credential records and strict spec-format wrapper
parsers. Additive PostgreSQL schema v2 preserves migration 001 unchanged and
verifies the ordered checksum ledger. It stores immutable wrapper sets, credential
epochs/revisions and tombstones, with expected-version writes, nonce uniqueness,
wire/column binding checks, and monotonic 2^20 limits for CEK writes and root-key
wraps. Stale/colliding/capped writes roll back; ciphertext history is retained.

`Service.ChangeAtomic` now puts trusted security writes, request invalidation,
lease revocation and revocation audit in one owner transaction. Prepared cache
buffers and catalog authority publish after commit under the same gate. Rollback
retains old authority; uncertain commit and publication failure lock access.
Tests exposed and fixed a slice-aliasing issue in prepared destination metadata.
The MCP/PostgreSQL integration now reads the actual stored encrypted records
through the adapter before publishing them to the real activator.

Added browser vault worker primitives for setup, passphrase/recovery unlock,
independent CEK creation, authenticated selected-key release, passphrase wrapping
changes and lock. Vendored hash-wasm 4.12.0 with license, npm integrity and hashes.
Argon2id uses the fixed spec profile and one-use child workers; no runtime CDN or
browser persistence. nginx serves module MIME types and a restrictive worker CSP.
The implementation does not claim guaranteed JavaScript/WASM memory erasure.

Validation on Go 1.27.1 / Node 20.19.2:

- `go build ./...`, `go vet ./...`, and **`go test -race ./...` with PostgreSQL
  enabled passed**. Tests include encrypted record CAS/contention, both nonce
  registries and caps, owner isolation, tombstones, immutable cache buffers,
  migration rollback/upgrade, publication failure and deferred commit rejection.
- All three UI test files passed; the six new vault tests also passed directly.
  Vendored Argon2 output matched two independent argon2-cffi vectors including
  whitespace, combining Unicode and international input.
- Go and Node WebCrypto authenticated root, recovery, CEK and credential envelopes
  in both directions. The original envelope interoperability tests also passed.
- Real Firefox 156 workers passed setup, passphrase/recovery unlock, selected CEK
  release, lock/cancel and new-worker lock checks under the intended CSP. No
  local/session storage entries or external requests were created. One desktop
  run observed setup 244 ms / passphrase unlock 152 ms; this is not mobile or
  cross-browser qualification.
- All 16 original security-spec hashes still match. Migration 001's bytes match
  the pre-edit baseline. No Go module or legacy argument-hash change was made.

Upgraded only the isolated PostgreSQL 18.6 base fixture to schema v2 using the
migration CLI. It has zero owners, vaults and credentials; no live data was
imported. All scratch databases and roles were cleaned up. The fixture remains
running for subsequent work.

Following the user's standing instruction, rebuilt and redeployed both Compose
services after validation. A stopped-gateway, protected data/configuration backup
is at `/tmp/mcpwarden-predeploy-20260923-vault-1/`; keys are separate at
`/tmp/mcpwarden-predeploy-keys-20260923-vault-1/`. The pre-edit source archive and
119-file hash manifest remain at `/tmp/mcpwarden-security-phase4-m6lvt_rw/`.

Gateway/UI are running with zero restarts on the new images (server `aebf3bcc947f`,
UI `14edadb03a34`). `/healthz` returned 200. Both gateway and UI-proxied APIs passed
unauthenticated rejection and authenticated access/history/filter checks, with
no-store responses. Served UI/crypto assets match source byte-for-byte; worker
module MIME/CSP headers passed. The prior audit log survived byte-for-byte, with
no new audit bytes introduced by verification. Volume mounts and deployment
credential keys were preserved. GitHub configuration remains as supplied.

This completes the tested primitive/persistence batch, not live client-release
rollout. Startup still uses legacy file custody; there are no owner vault routes
or vault screens wired into the panel. Owner authentication/CSRF and lifecycle
hooks, coordinated full catalog/history migration, initial discovery, OAuth
refresh, startup installation and restore/load qualification remain. See
[vault storage](security/vault-storage.md) for precise contracts and release gates.

## 2026-09-23 — Initial source snapshot and GitHub checks

Prepared the initial source commit and created the private
[YAPhoa/mcpwarden](https://github.com/YAPhoa/mcpwarden) repository at the user's
request. Ignored live configuration, environment files, encrypted catalogs,
audit logs, backups and installed browser dependencies. The staged source passed
a redacted Gitleaks scan; original spec files retain their published bytes.

Added pinned, read-only GitHub Actions workflows for Go formatting, module
consistency, build, vet, PostgreSQL race tests, CGO-disabled production checks,
bounded parser fuzzing, UI/crypto tests, Chromium/Firefox/WebKit workers,
dependency vulnerabilities, secret history, workflow syntax and isolated
container smoke tests. A single **Required checks** job aggregates every
mandatory result. CodeQL is separately available when the private repository
has Code Security enabled. Dependabot covers Actions, Go, npm and Dockerfiles.
No production secrets or deployment credentials are used by these workflows.

The new vulnerability check found a reachable normalization denial of service
through PostgreSQL connection setup in `golang.org/x/text` v0.29.0. Upgraded to
v0.39.0, the fixed version in
[GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970); the final scan found no
vulnerabilities. Sonic and the pinned MCP SDK are unchanged.

Validation on Go 1.27.1 / Node 20.19.2:

- `go build ./...`, `go vet ./...` and `go test -race -count=1 -timeout=10m ./...`
  passed with the isolated PostgreSQL fixture enabled. Module tidy/verification,
  CGO-disabled build and JSON/catalog tests passed.
- All UI/crypto tests passed. Playwright 1.63.0 passed real worker, KDF, recovery,
  CEK release, lock/cancel, no-storage and no-external-request checks in Chromium
  153.0.8010.12, Firefox 155.0 and WebKit 26.6. npm reported zero vulnerabilities.
  Hosted workflows select Node 24; these local results used Node 20.19.2.
- Two 10-second fuzz runs passed: 419,352 scope-parser and 311,428 envelope
  executions. actionlint passed; its optional ShellCheck integration was not
  available locally. All 18 spec/vendor integrity hashes matched.
- Disposable Compose image builds and API/static/worker smoke checks passed
  after the dependency fix. The fixture removed only its own containers,
  network and volume; live data was not used.

The ordered implementation backlog is in [pending tasks](pending-tasks.md).
Owner security routes, panel integration, full PostgreSQL catalog migration and
startup enforcement remain pending; current deployment custody remains the
legacy encrypted catalog.

Initial commit `9019942` was pushed to the private repository with `main` tracking
`origin/main`. Its [hosted CI run](https://github.com/YAPhoa/mcpwarden/actions/runs/35825326621)
passed every mandatory job on Ubuntu 24.04, including Node 24, the three browser
engines, PostgreSQL race tests, workflow checks, vulnerability/secret scans,
container smoke and the final aggregate check. CodeQL skipped as configured for
private repositories without the explicit Code Security opt-in. Actions and
Dependabot vulnerability alerts are enabled; Dependabot has opened its first
update proposal. GitHub returned HTTP 403 for repository rulesets, requiring an
account upgrade before private-branch check enforcement is available. No billing
or repository visibility changes were made.

Rebuilt and redeployed both services after a consistent stopped-gateway backup
at `/tmp/mcpwarden-predeploy-20260923-initial-1/`; keys are separate at
`/tmp/mcpwarden-predeploy-keys-20260923-initial-1/`. Gateway and UI are running in
new containers with zero restarts. Their built image digests remained server
`aebf3bcc947f` and UI `14edadb03a34`: this batch's dependency change affects the
separate database CLI, while current startup still uses legacy file custody.
Health, authenticated/unauthenticated APIs, no-store, served asset bytes, worker
MIME/CSP and preserved volume mounts passed. Previous audit history was retained
byte-for-byte. Deployment encryption keys and operator credentials were unchanged.

## 2026-09-23 — Supplied branding and favicon integration

Imported all 11 supplied SVGs unchanged. Sign-in, desktop navigation and the
mobile header now use the matching monogram/wordmark for the resolved Light,
Dark or System appearance. Loading uses the matching app icon, and README uses
a color-scheme-aware monogram. Dashboard links retain a single accessible name.
The supplied horizontal dark logo duplicates the light artwork, so the UI uses
the correctly colored component pairs; both original horizontal files remain.

Added the SVG favicon and, at the user's request, an ICO fallback rendered from
the same artwork with 16, 32, 48 and 64px frames. No runtime dependency or external
asset request was added. Brand files are served by the separate UI container.

Validation passed: `go build ./...`, `go vet ./...`,
`go test -race -count=1 -timeout=10m ./...` with PostgreSQL enabled, all UI/crypto
tests, and all 18 original spec/vendor integrity hashes. Chromium, Firefox and
WebKit verified light/dark sign-in and dashboard layouts at 1440, 390 and 320px,
manual/System theme changes, dashboard navigation and loading icons. No page
overflow, JavaScript error or external asset request was observed in these
synthetic browser fixtures. Desktop/mobile screenshots were inspected. All
three engines decoded both favicon formats; ICO frame sizes were also checked.

Rebuilt and redeployed both services. A protected, consistent stopped-gateway
backup is at `/tmp/mcpwarden-predeploy-20260923-brand-1/`, with keys separately at
`/tmp/mcpwarden-predeploy-keys-20260923-brand-1/`. UI image `b7e14c305b6d` and
gateway image `aebf3bcc947f` are healthy in new containers with zero restarts.
Live health, authentication/access/history boundaries, no-store and all 12
brand/favicon asset bytes and MIME types passed. The prior audit file was
preserved byte-for-byte with no new records from verification. Deployment keys
and volume mounts were preserved; application credential custody is unchanged.

The branding commit's hosted CI exposed a pre-existing asynchronous readiness
assumption in `TestGatewayIntegration`: registry discovery could be complete
while the downstream SDK was still registering tools. Corrected the test to
wait for the client-visible list at startup and after dynamic additions, with
the existing bounded poller and policy/notification/cancellation assertions.
The pinned SDK behavior is recorded in [decisions](decisions.md).

The corrected integration test passed 300 race-enabled repetitions across
`-cpu=1,2,4`. `go build ./...`, `go vet ./...` and the full PostgreSQL-enabled
`go test -race -count=1 -timeout=10m ./...` passed again. Rebuilding reproduced
the same deployed gateway/UI image digests; the correction changes only test
synchronization and documentation, with no shipped runtime change.

## 2026-09-23 — Stdio upstream environment allowlist

Stdio upstream commands no longer inherit unlisted gateway environment variables,
including `MCPWARDEN_CREDENTIAL_KEY` and the other deployment secrets. This filters
the child environment; process and host isolation remain open. See
[decisions](decisions.md) for the inherited variable list. A new stdio test checks
that an unlisted variable is absent while `PATH`, `LC_*` and explicit overrides
arrive exactly once; it fails against the previous behavior.

Validation passed: `go build ./...`, `go vet ./...` and
`go test -race -count=1 -timeout=10m ./...`. PostgreSQL-dependent cases were not
run against the compose fixture in this environment. Existing stdio upstreams
that relied on other inherited variables need them added to their `env` map
before redeploying.

Hosted CI passed on the branch head `800edeb` through a manual `workflow_dispatch`
run ([CI run 6](https://github.com/YAPhoa/mcpwarden/actions/runs/35843446238)),
including the Go race tests against the PostgreSQL service. The workflow does not
run on pushes to branches other than `main`, so feature branches need a pull
request or a manual dispatch.

## 2026-09-23 — PR #2 merge and deployment

Reviewed and merged [PR #2](https://github.com/YAPhoa/mcpwarden/pull/2) at
`a47ee62`, with the same source tree as the validated PR head `b719c08`.
The [acceptance matrix](security/acceptance-matrix.md) includes each of the 68
spec cases exactly once, and all 59 referenced Go test/fuzz functions exist.
Its library coverage does not imply live client-release enforcement.

The PR's [hosted CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35845920909)
and the merged commit's [CI](https://github.com/YAPhoa/mcpwarden/actions/runs/35868460589)
passed all mandatory jobs. CodeQL remained skipped for the private repository.
Before deployment, `go build ./...`, `go vet ./...`
and `go test -race -count=1 -timeout=10m ./...` passed locally with the isolated
PostgreSQL fixture enabled. Original spec and vendored crypto integrity checks
also passed. The live configuration has no stdio upstreams, so no additional
explicit environment entries were needed.

Built and redeployed the gateway and UI after a consistent stopped-gateway
backup at `/tmp/mcpwarden-predeploy-20260923-stdio-1/`; keys are stored separately
at `/tmp/mcpwarden-predeploy-keys-20260923-stdio-1/`. Backup directories are mode
0700 and files are mode 0600. Gateway image `2261fe7ed98b` and UI image
`b7e14c305b6d` run in new containers with zero restarts. Live health,
authentication/access/history boundaries, history filters, no-store, UI source
bytes and all 12 brand/favicon assets passed verification. Deployment keys and
volume mounts were preserved. The encrypted account/provider catalog and prior
audit bytes are unchanged, with no new audit records from the checks.

The deployed gateway still uses legacy server-managed credential custody.
Environment filtering is now deployed; process/host isolation and the owner
API/UI, catalog migration and guarded startup wiring remain pending.

## 2026-09-24 — Tool visibility panel restyle

Rebuilt the connector Tools tab from the user's tool-visibility mockup: a
searchable list with All / Shown / Hidden view counts, a view-scoped bulk menu
with a confirmation dialog, per-row switches with pending and retry states, and
expandable rows that show the MCP wire name and open the existing schema and
history dialog. The tool directory shares the same panel and keeps its upstream
filter. Connection settings are unchanged. No API or gateway change.

`node --test` UI suites (47 tests, including new view-scoped bulk, failed-save
retry and policy-blocked cases), `go build ./...`, `go vet ./...` and
`go test -race ./...` passed locally; PostgreSQL-backed tests skipped without
the fixture. Chromium was checked against a synthetic API at 1440px dark and
light and at 390px dark: bulk menu keyboard navigation and Escape, confirmation,
pending switch, expanded row, empty search and the directory view, with no
console errors and no horizontal overflow at 390px. Not redeployed.

## 2026-09-24 — Kaggle tool-call triage and string content repair

Triaged the Kaggle upstream issues by calling Kaggle's MCP server directly
without the gateway. `search_datasets` ignores `pageSize` there too (20 results
for 3 or 5), and `search_competition_submissions` returns `{}` directly as well.
The same "Permission ... was denied" errors come back directly. The gateway
forwards arguments as raw bytes and returns upstream results and error text
unchanged, so those items are upstream behaviour. The generic "An error
occurred invoking ..." text is not produced by the gateway or the SDK.

`tools/call` results whose `content` is a bare string or single object are now
wrapped into the array form before SDK decoding (see decisions.md). New tests
cover Streamable HTTP JSON and SSE bodies, stdio, and unchanged shapes; the new
HTTP and stdio tests fail without the change. `go build ./...`, `go vet ./...`
and `go test -race ./...` passed locally; PostgreSQL-backed tests skipped
without the fixture. Not redeployed.
