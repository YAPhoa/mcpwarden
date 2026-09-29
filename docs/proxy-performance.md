# Proxy performance

Timing is collected automatically for every routed upstream tool call, for all users, connectors, HTTP/stdio transports and both client/admin MCP access. No diagnostic mode is required. Data persists in the call history database and is available in the workspace and per-tool History views.

## Measurements

- `timing.handler_us`: handler entry until immediately before audit persistence.
- `timing.upstream_us`: time spent in Manager.Call, including SDK serialization/decoding, transport and upstream execution.
- `timing.gateway_us`: handler minus upstream time. Includes argument hashing, policy/visibility/approval and result classification.
- `timing.forwarded`: whether Manager.Call was invoked. Denied calls have no upstream sample.

Authentication before dispatch, audit writes, downstream SDK encoding and response delivery are outside these measurements. Do not interpret gateway time as all overhead or subtract unmatched direct/proxied remote calls to estimate overhead. Old audit events show their original duration only.

`GET /api/history` returns `performance` for **all matching records**, independent of pagination. Existing owner, connector, tool, status and time filters apply. Each latency summary exposes sample count, mean, maximum, and p50/p95 upper bounds from fixed logarithmic buckets. `failed_calls` counts non-success timed calls, including denials. Upstream averages exclude calls not forwarded. Workspace access remains isolated; this is platform-wide instrumentation, not cross-user access in the admin panel.

## How to evaluate changes

1. Compare the same connector/time window and separate success, timeout and tool/protocol failures with History filters. Inspect gateway and upstream distributions independently.
2. For actual end-to-end overhead, use a controlled local mock MCP server and a load generator. Compare warmed direct and proxied paths at the same concurrency, payload size and transport, recording p50/p95/p99, throughput and errors. Measure cold initialization separately. Never use real side-effecting tools as a load target.
3. Before optimizing, add separately scoped HTTP/auth and audit-write measurements if client latency is high while handler latency is low. Keep request duration distinct from long-lived MCP SSE session lifetime.
4. If volume grows, export bounded histograms to an operator-only metrics backend, with connector/transport/status labels; avoid user, session or tool IDs as unbounded metric labels. Use audit identities for detailed investigation. Add audit retention/indexing to avoid repeatedly scanning an ever-growing log.

## Kaggle diagnosis

Read-only tests reproduced the generic invocation failure for verbose pagination fields. Minimal pagination (`page`, `pageSize`) succeeded through the configured gateway. `authorize` returned malformed MCP content, causing SDK decoding to fail. The gateway previously closed the upstream session after that request error and the immediate next tool call failed. The gateway now preserves the session; malformed responses still correctly fail their own call. No upstream payloads or credentials were saved in diagnostics.

The direct diagnostic used an older OpenCode credential and had different minimal-query outcomes from the gateway, so those remote timings are not a controlled performance comparison and should not be used as an overhead claim.
