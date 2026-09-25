# MCPWarden security console

Selected direction: the supplied MCPWarden Style B security console recipe (2026-09-21). The frontend remains static HTML, CSS, and vanilla JavaScript, served by its separate nginx Compose service.

## Visual system

Dark canvas `#101722`, surface `#182332`, raised/selected surface `#223148`, decorative border `#3b4a60`, control border `#718198`, text `#f3f6fb`, muted text `#aab8ca`, accent `#a8c5ff`, on-accent `#112244`, success `#93dfb6`, stale/warning `#f6c975`, danger `#ffadb5`. Tokens live in `static/style.css`.

Use a 232px sidebar (224px on intermediate widths), 24–32px desktop gutters, 8px panel corners, 14px body text, 13px labels, and 24px page headings. Compact two-line list rows use explicit status text. Upstreams, connection details, and the tool directory are distinct hash routes. Opening a row navigates into its connection; details use two columns on desktop and one on mobile. The directory links back to the filtered connection. Mobile navigation sits above content. The registration form is 680px wide at most. Wide tool tables scroll inside their own region.

Use separate connection, discovery, saved-header, and agent-discovery sections. Green indicates recorded discovery or verified management access, amber marks stale snapshots, and red marks failures or removal. Discovery timestamps are not live health checks. Tool policy remains independent of connection status and visibility.

## API inventory

| Surface | Source or mutation |
| --- | --- |
| Gateway readiness and workspace | GET `/api/status`: `ready`, server-validated `session.mode`, `subject`, `username`, `authentication`, `management_scope` |
| Sign-in options | GET `/api/auth/options`: `mode`, `registration` |
| Account entry | POST `/api/auth/register`, `/login`, `/logout` with JSON and custom request header |
| Personal client token | POST `/api/auth/client-token` from an authenticated browser session; replaces previous token |
| Upstream list/details | GET `/api/providers`: `name`, `transport`, `source`, `healthy`, `error` presence, `tool_count`, `last_discovered`, `visibility_mode`, `enabled_tools` |
| Personal connection details | GET `/api/connections`: `name`, `url`, `call_timeout`, `header_names` |
| Tool inventory/schema | GET `/api/tools`: exact `name`, `upstream`, `description`, `allowed`, `healthy`, `visible`, `tool` schemas/annotations |
| Registration | POST `/api/connections`: `name`, `url`, `call_timeout`, new `headers` |
| Removal | DELETE `/api/connections/{name}` after confirmation naming the upstream |
| Explicit refresh | POST `/api/discovery/{name}/refresh`; no tool invocation |
| Discovery visibility | PUT `/api/providers/{name}/visibility`: `mode`, exact names in `enabled` |

Only verified successful API reads enable mutations. A transient read failure retains the prior snapshot, labels it as such, and disables management actions. HTTP 401 and 403 clear the previous inventory. There is no automatic polling that can disrupt editing or keyboard focus; operators reload inventory explicitly. Failed refresh attempts remain marked in page memory until an explicit successful refresh. The gateway does not persist a separate latest-refresh outcome.

## Credential and capability boundaries

Manually entered bearer tokens stay in page memory. Basic account sign-in uses an HttpOnly session cookie; the UI does not handle its value. Personal client tokens are created only on explicit request, returned once, copied on demand, and cleared on dialog close. The encrypted store keeps only their hashes. The legacy sessionStorage token key is removed without reading it. New header values are password inputs, submitted only on registration and cleared when the dialog closes. Saved headers display names and “Stored”; values are never fetched. API diagnostics may contain sensitive upstream content, so the UI uses generic HTTP diagnostics and never renders raw error strings. Returned names, endpoints, descriptions and schemas are escaped or assigned as text.

The API lacks saved-header update semantics, plaintext retrieval, audit reads, and a distinct disabled-entry state. Those controls are not invented. A missing managed storage configuration (HTTP 501) leaves config upstreams inspectable while disabling unsupported mutations. Remote registration cannot launch stdio processes.

## Review evidence and remaining checks

- `node --check ui/static/app.js`: passed.
- `node ui/tests/app.test.cjs`: 11 synthetic controller tests passed. Added separate-route/deep-link and server-identity coverage. Covers empty vs zero tools, never discovered, discovery failure, cached/stale results, pending/failed refresh, escaping, snapshot retention, 401/403 inventory clearing, config stdio without managed storage, filtering/selection, and exact visibility mutation payloads.
- `go build ./...`, `go vet ./...`, `go test -race ./...`: passed after account changes, including account isolation, session rotation/logout/expiry, CSRF/origin rejection, hashed persistence, client token rotation, and registration configuration checks. Loopback-dependent tests required execution outside the filesystem/network sandbox.
- Contrast calculated from specified opaque CSS tokens: normal text combinations at least 6.50:1 across canvas/surface/raised; accent-button text 9.05:1; control borders at least 3:1. This is token math, not a rendered accessibility scan.
- Browser runtime reported no available browsers. No screenshots, rendered 1440/1024/390px or 200% zoom review, actual keyboard/focus-return testing, touch testing, network/storage inspection, or browser accessibility scan was possible. These remain required visual acceptance checks. Automated controller tests do not simulate real DOM layout or native dialog behavior.
- Code review found the original token persistence and conflated policy/offline labels; both were corrected. No backend capability was added to support the design.

## Account flow and navigation revision

User explicitly requested basic panel registration on 2026-09-21, extending the original token-only scope. Sign-in is the normal entry screen when `accounts` is configured. Registration uses a username and confirmed passphrase; credentials are submitted to the gateway and never stored by frontend code. Sidebar identity distinguishes personal accounts, OAuth subjects, and the shared operator workspace. Existing operator connections are not reassigned to new accounts.

Routes: `#/upstreams` (overview), `#/upstreams/{name}` (connection settings), `#/tools` (all tools), and `#/tools/{name}` (filtered directory). Hash changes implement Back/Forward, direct links, current navigation state, and heading focus. An unavailable deep link stays explicit rather than opening another connection. Filters remain separate from ownership enforcement.

Browser tooling remains unavailable in this active session. The user installed Playwright MCP for the CLI in another session; its tools are not loaded here yet. Start a new Codex session, confirm Playwright with `/mcp`, then perform the rendered and keyboard checks above using synthetic accounts and fixtures.

## Firefox browser review — 2026-09-21

Playwright MCP became available. Inspected the live sign-in screen, then used an isolated gateway, encrypted temporary catalog and local mock MCP upstream for account/workflow checks; no test users were added to the live workspace.

Observed and corrected: fresh visits showed a premature red authentication error; Firefox rejected unescaped hyphens in HTML validation patterns; sign-out after registration retained the create-account form; unavailable provider tool routes could show another provider's inventory under the wrong label. Added two controller regressions (13 total tests passing).

Browser-confirmed: registration and sign-in; separate Alice/Bob workspaces; Alice's saved connection and visibility surviving sign-out/sign-in; upstream registration with masked headers; successful three-tool discovery; selected-tools visibility; exact schema inspection; separate overview/detail/directory routes and Back navigation; named removal confirmation and cancel; Escape and focus return for add/schema/removal dialogs; personal token generation and authenticated use; token cleared on dialog close. The synthetic header value was absent from the list response, and localStorage/sessionStorage remained empty. Untrusted HTML in a tool description rendered as text.

Visually inspected screenshots at 1440px (login, connection, directory), 1024px (overview), and 390px (connection, directory, registration dialog). No page-wide horizontal overflow was measured in the narrow connection/directory pages; the registration dialog stayed inside the viewport. Native 200% browser zoom, screen-reader use, a full keyboard-only journey, and a complete accessibility scanner pass remain untested.

Remaining polish: mobile navigation/account context consumes substantial vertical space; tool visibility controls sit beyond an internally scrolling table at 390px. The desktop layout is clear, but mobile tool rows would benefit from a more compact presentation with visible actions.

## Dashboard and connector tool management — 2026-09-21

Applied the user's latest screenshot feedback. The root route and `#/dashboard` open a workspace dashboard, with actual upstream count, discoverable tool count, and unavailable/stale discovery count. The overview links into connectors; the top breadcrumb uses a real Upstreams link. Explicit existing deep links remain supported.

Each connector now shows its tool list first. Connection settings are in a native expandable details section below. The shared tool panel also serves the full directory, retaining its event handlers when moved between routes. It supports 10/25/50 rows per page, previous/next, a search toggle, text search, and discoverability filters. Search/filter/page state is scoped to the connector and cleared when changing account. Filtering or page-size changes reset to page one; mutations clamp the page if a filter removes its final row.

Discoverable is exactly `allowed && healthy && visible`, matching the gateway's advertised-tool condition. Enable switches edit only the server's visibility setting; policy-denied tools stay in the inventory with disabled switches, and unavailable tools remain explicitly marked. Mutations build enabled sets from the complete upstream inventory, never only the current search or page. Pagination is client-side over the already loaded management inventory.

Mobile tool rows stack with visible labels, status, and switches instead of horizontal scrolling. Browser-tested using an isolated gateway with 71 synthetic tools: dashboard landing, connector pagination, search, discoverable/not-discoverable filters, per-tool mutation, updated dashboard totals, breadcrumb navigation, and 25-row page size. Inspected 1440px dashboard/connector screenshots and 390px tool rows; no page-wide horizontal overflow on the narrow dashboard or connector. Sixteen controller tests and Go build/vet/race checks pass. Native zoom and a full assistive-technology audit remain outside this verification.


## Tool identity, provider availability, and authentication — 2026-09-21

Tool rows and schema headings now display the original upstream tool name. UUIDs identify UI actions; connector names remain a separate column, and schema details show the unchanged MCP wire name. Existing visibility payloads retain those wire names. The provider switch sits beside the connector heading; pending changes are shown without snapping the switch back, and disabled providers are not counted as failures requiring attention.

The registration form offers no authentication, bearer token, API-key header, custom headers, and OAuth. Only fields for the selected method are active. Credentials are masked and cleared when the dialog closes. OAuth client fields are optional for dynamic registration, with the exact callback URL displayed for preregistration. Connect/reconnect account is visible at the top of the connector page. Consent opens in a separate window with no opener; completion asks users to close it and reload inventory.

Firefox verified the complete mock OAuth flow and the provider switch, including preservation of individual tool choices. Reviewed 1440px connector and 390px connector/OAuth-form screenshots. Nineteen controller tests pass. Real Google Drive integration remains untested because no Drive MCP server has been selected.


## Visible provider actions — 2026-09-21

Upstream list and dashboard rows now place Refresh tools and a labeled enable switch beside the connection link. Controls are siblings of the link, allowing direct actions without navigating. Narrow screens place actions on a second row. Connector refresh moved into the heading beside its enable control. Verified actual refresh and toggle API calls in Firefox on an isolated fixture, desktop layout and 390px layout without horizontal overflow.


## Connector toolbar refinement — 2026-09-21

Applied the 12:42 screenshot feedback: permanently visible search field with adjacent discoverability/provider filters, consistent heading-action alignment, and a prominent plain Refresh button. Removed the upstream column from connector-scoped tables; the all-tools directory retains it. Search remains scoped per connector and filters/pagination still work.

Checked Firefox at 1440px and 390px, searched a 71-tool fixture, verified single-connector column removal and all-tools column retention, and measured no mobile overflow. JS syntax, 19 controller tests, and Go build/vet/race checks pass. Rebuilt only the UI service.


### Access and provider summaries

Access owns client connection setup, named key creation with explicit Client/Admin role, session/device identity, expiry, rename/revoke, and historical records. Key values are shown once and cleared on dialog close. Three counters reflect the backend's hard active limits. OAuth revocation copy explains its local scope.

Upstreams includes workspace enabled/disabled/total provider totals and saved tool-choice counts on each row. Connector tool actions enable or disable the entire upstream independent of filters; provider pause preserves those choices. Pending switch saves disable existing controls in place to preserve native checked state and geometry until the new snapshot arrives.

Connector state uses explicit red Disable connector and green Enable connector buttons with stable widths, followed by Refresh on the right. Bulk-action scope guidance lives in an “i” disclosure.

Tool directory upstream filtering uses a compact checkbox menu with multi-selection, a selection-count label, and Show all reset. Bulk-action information uses hover and keyboard focus instead of a click disclosure. Toolbar controls and connector actions use compact 32–34px heights.

List views use connector switches; focused connector pages use Enable / Disable buttons. Connector state and saved per-tool visibility are independent; effective discovery requires both, plus policy and availability.

Tool-table Discovery badges/counts/filters describe tool visibility plus policy, independent of connector availability. Connector status and effective MCP exposure remain separate.

Appearance offers Light, Dark, and System from sign-in and the workspace header. A non-sensitive localStorage preference is applied before stylesheet rendering; System tracks OS changes. Inventory reload retains mounted content when its data is unchanged and keeps the reload button label and opacity stable.


History is a separate workspace page with local-time range, outcome, and tool filters, plus 25-record pagination. Tool dialogs offer Details/History tabs, with keyboard navigation. Both show response metadata only. Refresh all belongs on Upstreams and skips disabled connectors. Access contains MCP setup instructions. The sidebar ends with an expandable Account & appearance menu for theme, sign-out, and local password changes; it remains accessible on mobile and scrolls at short viewport heights.

History groups calls within each page by upstream service; upstream selection scopes the optional tool dropdown. Time bounds have explicit date, hour and minute controls. Authentication and connector availability are separate compact top-right header indicators; authentication alone never indicates green readiness.

### Clean URL routing (2026-09-22)

UI routes now use `/dashboard`, `/upstreams`, `/upstreams/{name}`, `/upstreams/{name}/settings`, `/tools`, `/tools/{names}`, `/history`, `/access` and `/settings/{section}`. Same-origin navigation uses History API pushState/popstate; modified clicks retain normal browser behavior. Legacy `/#/...` bookmarks are converted with replaceState. Hosting must serve index.html for UI deep links, as the supplied Nginx configuration already does; `/api/` remains separately proxied.

### Supplied brand assets (2026-09-23)

The user's SVG set is stored unchanged in `static/brand/`, with the primary
browser icon at `static/favicon.svg`. The user also authorized the ICO fallback
at `static/favicon.ico`, rendered from that same SVG with 16, 32, 48 and 64px
frames. No fonts, CDN requests or new runtime dependencies are needed to render
the branding.

Sign-in, desktop navigation and the mobile header pair the matching monogram and
wordmark. CSS follows the existing resolved Light/Dark/System preference; each
dashboard link has one accessible name and its artwork is decorative. The loading
screen uses the matching square app icon. The README also adapts its monogram
to the reader's color scheme.

The supplied `logo-horizontal-dark.svg` and `logo-horizontal-light.svg` have
identical light-background artwork. Both original files are retained; the UI
uses the separate, correctly colored monogram/wordmark pairs. Monochrome variants
are also available for future uses.

### Vault and access windows (2026-09-24)

`/vault`, `/vault/credentials` and `/vault/settings` form the owner console. It is
a separate module (`static/security/owner-console.mjs`, with DOM-free helpers in
`owner-core.mjs`) that listens for `mcpwarden:identity` and `mcpwarden:route`
events from `app.js`. It uses the existing settings cards, access rows, badges,
dialogs and filter controls; no new colors or fonts were added. Countdowns use
tabular numerals. Below 700px the status controls, facts and row actions stack.

The page appears only for local accounts with `owner_security` enabled. A
disabled API, untrusted transport, storage failure or shared operator/OAuth
workspace gets a plain status line and no controls. A note on every visit says
what windows limit. With `custody_mode: legacy_managed` (the default, from
`/api/vault/state`) they do not yet limit ordinary tool calls, which still use
gateway-managed credentials. With `client_release` (2026-09-25) the note, the
credentials help, the save dialog and the remove dialog say that a connector
with a vault credential runs only inside access windows, that the gateway stops
using its own header copy, and that a removed credential keeps the connector
locked. Connections in vault custody show "Vault custody" instead of a
connection state in the main console, count as available, and have Refresh
turned off.

| Surface | Source or mutation |
| --- | --- |
| Vault and policy state | GET `/api/vault/state`; GET `/api/vault/wrappers` (root wrappers, credential metadata, wrapped keys and current envelopes) |
| Setup and passphrase change | POST `/api/vault/setup`; PUT `/api/vault/wrappers` with `expected_wrapper_revision` and the account password |
| Credentials | PUT `/api/vault/credentials/{id}` with the expected epoch and revision, or `null` when new |
| Requests | GET `/api/access-requests[/{id}]`; POST `/api/approvals/{id}/begin`, `/deny`, `/activate` (Idempotency-Key); owner renewal POST `/api/access-requests` |
| Windows | GET `/api/leases?include=ended` (active plus the last 24 hours, at most 50 ended); DELETE `/api/leases/{id}` |
| Locks and policy | POST `/api/vault/lock-execution`; PUT `/api/security/approval-policy` |

Owner requests send the session cookie, `X-MCPWarden-Request` and the CSRF token,
never an Authorization header. Setup shows the recovery key once as 14 groups of
Crockford base32 with a checksum. Setup finishes only after the owner types the
key back and it opens the recovery wrapper; nothing is uploaded before then.
Unlock offers the passphrase or the recovery key. Credential dialogs are
password fields for each existing header name of an HTTPS or loopback HTTP
connector. They are cleared before encryption, and replacing a credential starts
a new epoch under the same credential ID.

Request cards show the caller label and public key handle, key expiry,
credential version, endpoint and header names, tools with their descriptions and
argument constraints, duration and call limits. Labels and descriptions are text
nodes styled as untrusted. `confirm` mode's button reads "Allow for 15 minutes";
`none` reads "Start access for 15 minutes". Both release one credential key from
this browser. A response lost in transit keeps its Idempotency-Key and offers
"Check status" and "Retry the same activation", never a fresh grant.

Window cards show the exact end time, a countdown from the gateway's `Date`
header, call counts, and approval details. They can be filtered by state, caller
and connector. States are Active, Provider unavailable, Ended, Stopped and
Suspended; requests show Waiting for your review and Approved · not active yet.
Renew opens a dialog (5, 15, 30 or 60 minutes, default 15) and creates a new
request and window. If the new request's scope differs from the one shown, for
example after a tool definition changed, the dialog shows the new scope and
starts nothing until the owner allows it again. Cancel or Escape while a
renewal or unlock is pending stops it; nothing is approved, released or unlocked
afterwards. A credential save cancelled after its upload was sent reports the
result as a page notice or error, and never closes or clears a credential form
opened after it. "Lock browser" only terminates this browser's vault worker;
"Stop access" ends one window; "Lock all execution" ends every window after a
confirmation dialog. Browser lock also happens on sign-out, account change,
leaving `/vault`, page hide and 10 minutes without input. Each lock discards any
response still in flight.

Remove (2026-09-25) sits beside Replace on a stored credential and works while
the vault is locked, since it needs no key. A confirmation dialog focuses "Keep
credential" first. Removal writes a tombstone: the connector shows "Removed from
the vault" and cannot get a vault copy again, and pending requests and windows
end. The gateway-managed header is untouched. nginx sends the page CSP the
browser flows use; the flows also check layout at 720 px (200% zoom on a
1440 px laptop).

## Tool visibility panel (2026-09-24)

The connector Tools tab follows the user's supplied tool-visibility mockup. The
heading gains a connection icon, and the Tools tab shows its count as a pill.
The panel is titled Tool visibility and uses a search field with a clear button,
an All / Shown / Hidden segmented view with counts, a Bulk actions menu, a
Tool / Show to clients list head, and rows with the tool name, description,
state word and switch. Footer text gives the tool total; pagination (10/25/50)
stays in the footer.

Shown means discoverable (`allowed && visible`), as before. Policy-denied tools
read “Blocked” with a disabled switch, count as hidden and are never changed by
bulk actions. Rows expand in place to show the MCP wire name, upstream (in the
directory) and status, with a button that opens the existing schema and history
dialog.

Bulk actions now apply to the current view: every tool matching the search and
view across all pages, not only the visible page. The menu names the scope and
counts; a confirmation dialog states what changes and what stays. Every bulk
save keeps policy-blocked tools' saved choices. On the unfiltered view, Show
sends `mode: all` (tools found later are shown) only when no blocked tool is
saved as hidden; otherwise, and for Hide and narrowed views, it sends
`mode: selected` with the full enabled set for the upstream. The directory hides bulk actions unless a single upstream is selected.

A switch save marks its row “Updating…” with a spinning knob. A failed save keeps
the previous state and shows an inline error with Retry. The error remembers the
requested visibility, so Retry repeats that request, and it clears once a later
switch, bulk save or reload reaches that value. Successful changes post
a short toast. A note above the list explains read-only snapshots, missing
managed storage, and disabled or disconnected connections. Panel tokens are
defined for both Dark and Light themes. Connection settings are unchanged.

Follow-up (2026-09-24): after using the merged panel, the user found the text too
small and the page too empty. The panel now fills the content width, lining up with
the heading actions, and its type is one step larger: tool names 14px, descriptions,
view options and search 14px, secondary labels 12–13px.

Site-wide type (2026-09-24): the user asked for the same text-size increase across
the whole console. Every size outside the tool panel moved up one step (base 15px;
11→12, 12→13, 13→14, 14→15px; larger headings unchanged). Dashboard status badges
no longer wrap their arrow onto a second line on narrow screens.

Type scale (2026-09-24): the main text sizes are as follows. 12px is
for uppercase eyebrows, list headings and small counts; 13px for help text, row
metadata, badges and field labels; 15px for body text, navigation, menu items,
tabs and form values; 16px for tool and history rows; 18px for card and section
headings. The sidebar account launcher and its menu now match the navigation
(name and items 15px, secondary lines 13px). The menu items read Account,
Appearance and Security, matching the settings tabs. The 11px list headings and
calendar labels moved to 12px. History drops the "How timings and retention
work" disclosure, whose points were repeated elsewhere on the page, for one
line defining the timing columns and stating that payloads are not kept.

Dashboard stats (2026-09-24): the user reads the console on a 14" 1440p laptop
and asked for 18px as the minimum on the stat cards. Each card now has an 18px
label, a 36px number and an 18px line with live detail: enabled and disabled
counts, "of N found" for tools agents can use, and the names of connectors that
need attention (or "All connected"). That card turns amber when a connector needs
attention and green when all are connected.

Minimum 15px (2026-09-24): after trying and reverting an 18px minimum, the user
chose 15px as the baseline. Help text, metadata, labels, badges, menus and
controls that were 12–14px are now 15px. Only uppercase captions, the tool-count
tab pill, upstream tags and the "This session" tag are 13px, and view counts
14px. h3 is 16px so headings stay above body text. The dashboard stat cards
keep their 18px labels and detail lines.
