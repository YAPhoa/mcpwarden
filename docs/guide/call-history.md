# Tool call history

## In the panel

The **History** page lists your workspace's recorded calls with tool, local time, outcome, duration, and response metadata.

- Calls are grouped by upstream service on each page. Pages contain 25 calls, newest recorded first.
- Filter by a From/Until date and hour/minute range (Until is exclusive), status, or upstream service; an optional tool filter narrows the selected service.
- Ranges match when a call finished, or when it was admitted if its outcome is unknown. The list shows start times, so a call that started before a range but finished inside it is listed.
- Counts and timings cover the newest 25,000 matching calls. More matches show as "25,000+"; use the time range to reach older calls.
- Each tool's detail dialog also has a scoped **History** tab.

## API

The authenticated management API is:

```
GET /api/history?upstream=...&tool_id=...&status=...&from=...&to=...&page=...
```

The response carries `total` and `total_capped: true` when more than 25,000 calls match; `total` and `performance` then cover the newest 25,000.

- Timestamps use RFC3339.
- It never accepts a user/owner parameter and excludes session IDs and argument hashes from its response.
- `actor_access_id=...` filters calls made through one access record (see [API keys](accounts-and-access.md#key-format-and-public-ids)).
- Client credentials cannot read history.

## How calls are recorded

History is in the gateway's database ([storage](../storage.md)).

- Admission is committed before any upstream or gateway-management MCP action. Failed admission blocks execution.
- Completion is written separately. Failure to record completion preserves the actual result and never retries the action.
- History shows unmatched admissions as **Outcome unknown**, which may include work still running. It is not evidence of failure or safe retry.
- SDK validation failures before handler dispatch are not call records.
- Payloads, result bodies, raw errors and verifiers are not retained in history.

## Retention and scale

Call records are append-only. Stored tool UUIDs and name snapshots preserve history when a tool or connector is removed; connector deletion does not cascade into call history. Reserved management tools use their stable gateway names as IDs.

Each page reads indexes and at most the newest 25,000 matching calls. Use time filters for older records. Nothing is deleted; there is no retention policy yet.

Calls made through `--stdio` are recorded for owner `local`, with actor type `stdio`; the panel shows them in operator mode.

The stored format is described in [storage](../storage.md#history).
