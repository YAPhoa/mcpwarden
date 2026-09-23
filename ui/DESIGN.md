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
