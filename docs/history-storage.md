# History storage contract

History is append-only JSONL by default, or the indexed `history_events` table
with the PostgreSQL catalog backend (see the end of this page). `audit.Appender`
is the dispatch write boundary; `audit.Reader` is the query/aggregation boundary;
`audit.Store` combines them for the runtime. The application owns closing the
backend.

Legacy v1 rows represent completed invocations, including failures and denials:

- `schema_version`: 1; readers also support v0 and the current v2 below.
- `event_id`: unique identity assigned by `audit.NewRecord` before persistence.
- `ts`: UTC call start; From/Until filters continue to use this field.
- `completed_at`: UTC completion before persistence and response encoding.
- `owner`, `tool_id`, `upstream_id`: stable identities. Gateway management tools
  use their reserved names as tool IDs and have no upstream ID.
- `tool`, `upstream`: name snapshots independent of the live catalog.
- Existing outcome, duration, timing, response metadata and argument hash fields
  retain their meanings. Raw arguments, results and credentials are not stored.

Live handlers now write schema-v2 events:

- `invocation_id`: shared by an admission and its completion; every event keeps
  its own `event_id`. A denial before admission is a single event.
- `event_type`: `tool.dispatch.admitted`, `tool.dispatch.completed`, or
  `tool.dispatch.denied`. Admission records an authorized dispatch attempt; it
  does not replace authentication, policy, visibility, or future lease checks.
- `occurred_at`: event time. Admissions have no `completed_at`, timing, response
  claims or result; their `status` is `unknown` and decision is `allow`.
- `actor_type`, `actor_access_id`, `actor_public_id`, `actor_label_snapshot`:
  safe validated caller metadata, independent of clientInfo and tool arguments.
  Public IDs are independent random identifiers, not verifier/token suffixes.
  Legacy operator/storeless OAuth modes report only actor type, never their
  verifier-derived binding IDs. Historical missing actors are not backfilled.
- `argument_hash_version`: `mcpwarden.arguments.v1`, documenting the existing
  Go JSON decode/re-encode canonical hash without changing any hash bytes. This
  remains separate from future RFC 8785 approval-scope hashing.

The writer syncs admission before dispatch. A failed/uncertain admission write
blocks the upstream or gateway-management MCP action with a safe tool error.
Completion is a separate append. Its failure preserves the actual tool result
and never triggers retry. Unknown outcome can mean still running, a crash before
network dispatch, an executed action without completion logging, or other uncertain
persistence. It is not proof that execution happened or that retry is safe.

History pairs v2 events by owner and invocation ID, showing each invocation once.
Unpaired admissions remain visible with `status: unknown`, no completion time,
and no invented timing/response. They do not enter performance aggregates. The
history API omits response-count/structured/duration fields for these unknown rows;
zero-valued fields in the stored admission carry no completion meaning. The
reader supports reordered imports as well as normal admission-before-completion
append order. It retains pending/unpaired identity state in addition to the
bounded page heap; memory can grow with unresolved calls or heavily reordered
imports. The JSONL writer does not deduplicate event retries. Importers must enforce
unique event IDs and one admission/completion per invocation. This backend remains
single-writer; an indexed adapter is needed for large history.

History sorts by `(completed_at DESC, event_id DESC)`, with lexical event-ID ordering
as the tie-breaker, independent of arrival/import order. Clock adjustments can affect
completion order; this is not causal ordering. Page-based pagination can shift during
new writes. Tool options use the latest snapshot in this order for the owner, across
all their records. Performance summaries cover all matches, not just the current page.
Unresolved admissions use `occurred_at` for ordering instead of a fabricated
completion. `actor_access_id` filters are owner scoped; old unattributed calls do
not match. Existing handler/upstream/gateway duration fields still exclude audit
persistence; v2 proxy timing additionally reports `admission_us` separately.

Versionless records remain v0 on disk. Readers derive completion from start plus
duration and derive a deterministic UUID from the original line number and contents.
Repeated imports must preserve source lines or persist the normalized IDs in migration
output. Missing historical provider IDs remain unknown; do not attach records to new
providers by name. Ownerless records remain inaccessible. Empty owners return no data.

A future database adapter should preserve event IDs and enforce uniqueness on
`event_id` or `(owner, event_id)` for retry/import deduplication. JSONL itself does not
deduplicate writes; callers do not automatically retry. Retain the original event ID
when retrying persistence, and never retry the tool operation because auditing failed.
Import legacy data through a migration path preserving v0/v1 metadata, not the live v2
writer. Index owner plus completion/event ID, then owner/tool/start and
owner/provider/start as usage requires. Never cascade-delete historical records.
Preserve owner filtering, time bounds, tool options and timing-summary semantics.

JSONL supports one Writer/process per file. Successful file writes and initial
directory entries are synced before returning. History scans hold the writer lock
for consistency; large logs still need an indexed backend. Empty-path/stdout Writer
sinks can accept legacy diagnostic records but reject dispatch-admission writes.
Gateway startup rejects `audit.path: "-"`; an omitted path defaults to `./audit.jsonl`.

Malformed rows, unsupported schemas and incomplete v1 records fail reads. Startup also
rejects unterminated final lines so subsequent appends cannot merge with truncated
records. No silent skipping or automatic truncation occurs; preserve and explicitly
repair damaged files. Failed/short writes or sync failures stop further writes through
that Writer because persistence is uncertain. Both proxy and management calls log
safe identifiers for audit errors. No raw storage/provider error is copied to the
invocation event or its diagnostic. Process termination can leave only admission.
Live JSONL admission does not yet reserve a lease/call budget or coordinate with
revocation. The new [lease/PostgreSQL core](security/lease-storage.md) tests those
transactions separately; gateway integration and full legacy-history migration
remain required. Its leased-invocation table is not yet an `audit.Store` reader.

## PostgreSQL history

With `managed_upstreams.backend: postgres`, `pgcatalog.History` is the
`audit.Store`. Each record is one row in `history_events` that keeps the exact
JSONL bytes the file writer would have written, plus indexed columns derived
from them: owner, event and invocation IDs, schema version, event type, tool ID
and name, upstream, status, actor, start and ordering times in nanoseconds,
timing values and their log2 buckets. Every write is its own committed
transaction, so an admission is durable before dispatch. A failed or uncertain
write is returned and never retried as a tool call. A lost session also stops
the gateway.

Imported rows are `source='legacy'` with their original line number, so v0 IDs
derived from line and bytes stay valid. Live rows are `source='live'` in commit
order. `(owner_id, event_id)` and `(owner_id, invocation_id, event_type)` are
unique, and the runtime role can only insert. Queries return what the JSONL reader
returns: the same owner scoping, filters, hiding of admissions that have a
completion, ordering by completion (or occurrence) time and then event ID in
byte order, tool options and timing summaries. Latency summaries are rebuilt
from stored bucket counts, sums and maxima. Their means are sum/count, which can
differ from the reader's streaming mean in the last floating-point digits.
`TestImportPreservesCatalogAndHistory` compares both readers on the same data.
A rollback writes the imported bytes back followed by the live rows, so the file
backend continues the same history.
