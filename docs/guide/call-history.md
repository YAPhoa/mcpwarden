# Tool call history

## In the panel

The **History** page lists your workspace's recorded calls with tool, local time, outcome, duration, and response metadata.

- Calls are grouped by upstream service on each page. Pages contain 25 calls, newest recorded first.
- Filter by a From/Until date and hour/minute range (Until is exclusive), status, or upstream service; an optional tool filter narrows the selected service.
- Each tool's detail dialog also has a scoped **History** tab.

## API

The authenticated management API is:

```
GET /api/history?upstream=...&tool_id=...&status=...&from=...&to=...&page=...
```

- Timestamps use RFC3339.
- It never accepts a user/owner parameter and excludes session IDs and argument hashes from its response.
- `actor_access_id=...` filters calls made through one access record (see [API keys](accounts-and-access.md#key-format-and-public-ids)).
- Client credentials cannot read history.

## How calls are recorded

Tool dispatch requires a file-backed `audit.path` (the Compose default); stdout (`-`) is rejected at startup.

- Admission is synced before any upstream or gateway-management MCP action. Failed admission blocks execution.
- Completion is appended separately. Failure to record completion preserves the actual result and never retries the action.
- History shows unmatched admissions as **Outcome unknown**, which may include work still running. It is not evidence of failure or safe retry.
- SDK validation failures before handler dispatch are not call records.
- Old ownerless records remain excluded; payloads, result bodies, raw errors and verifiers are not retained in history.

## Retention and scale

Call records are append-only. Stored tool UUIDs and name snapshots preserve history when a tool or connector is removed; connector deletion does not cascade into call history. Reserved management tools use their stable gateway names as IDs.

Reads scan JSONL with bounded page selection (up to page 1000) plus state for unpaired admission/completion events. Use time filters for older records. For high-volume use, an indexed store and explicit retention policy remain necessary.

The storage format is described in [the history storage contract](../history-storage.md).
