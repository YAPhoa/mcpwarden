# Kaggle MCP: generic invocation error for a null pagination token

Status: reproducible request variant; upstream implementation cause unconfirmed.
Reported: 21 September 2026.
Tool: `search_competition_submissions` (gateway name `kaggle-mcp__search_competition_submissions`).
User evidence: Screenshot From 2026-09-21 23-38-25.png shows repeated invocation failures. Follow-up Screenshot From 2026-09-21 23-45-25.png supplies the reported failing fields and successful controls.

## Findings

The screenshot's assertion that all explicit pagination fails is too broad. In fresh read-only calls through the configured gateway, the properly wrapped request with `page: 1`, `pageSize: 50`, `hasPage: true`, `hasPageSize: true`, and `hasPageToken: false` succeeded twice. Each presence flag also succeeded individually.

Adding `pageToken: null` to that successful request reproduced the generic tool error. Adding only `pageTokenNullable: null` did not. The schema inspected earlier in this session advertised `pageToken` as string-or-null, making a null-induced generic error inconsistent with the advertised contract.

Sending the same fields directly as tool arguments without the required `request` wrapper also reproduced the generic error. The follow-up screenshot explicitly includes `pageToken: null`, along with `pageTokenNullable: null`, `pageNullable: 1`, and `pageSizeNullable: 50` in the reported failing variant. This matches the independently reproduced null-token failure and makes it the strongest supported explanation for this report. The successful controls omit these pagination fields. Both successful and failing examples are displayed without an outer wrapper, so their presentation does not establish a wrapper bug; treat the unwrapped-request test as a separate invalid-input case. The screenshot reports four failed attempts; those counts are user-supplied, not four additional tests performed here.

## Reproduction

Use a configured Kaggle identity and a competition it can access. The following is an illustrative request, with a placeholder competition rather than recorded user arguments:

```json
{
  "name": "search_competition_submissions",
  "arguments": {
    "request": {
      "competitionName": "<accessible-competition>",
      "group": "All",
      "sortBy": "Date",
      "page": 1,
      "pageSize": 50,
      "hasPage": true,
      "hasPageSize": true,
      "hasPageToken": false
    }
  }
}
```

1. Call the tool with the above shape: succeeds in this test.
2. Add `"pageToken": null` inside `arguments.request`.
3. Call again: HTTP 200, MCP result `isError: true`, with `An error occurred invoking 'search_competition_submissions'.`
4. Remove `pageToken`: the control request succeeds again.

## Observed test matrix

All calls used the same configured gateway credential. Success means the tool returned no MCP error; this investigation did not verify pagination completeness or returned submission counts. No raw result payloads or credentials were retained.

| Variant | Result |
|---|---|
| Minimal wrapped request | Success |
| Wrapped request + page/pageSize | Success |
| Above + hasPage:true | Success |
| Above + hasPageSize:true | Success |
| Above + hasPageToken:false | Success |
| Wrapped page/pageSize + all three flags | Success |
| All flags + pageToken:null | Generic tool error |
| All flags + pageTokenNullable:null | Success |
| All flags without request wrapper | Generic tool error |
| Properly wrapped all-flags control, repeated | Success |

## Expected behavior and suggested upstream action

- A null value permitted by the tool schema should have defined handling, or the schema should disallow it. If null means absent, normalize it before pagination processing.
- Missing required arguments should return an actionable validation error identifying the missing `request` field.
- Investigate pagination argument binding/token processing in the Kaggle MCP implementation. A particular language/framework/setter defect is not established by these tests.

## Current workaround

Keep arguments inside `request`. Use `page` and `pageSize` when needed, and omit unused `pageToken` entirely. Explicit pagination itself is not generally broken in the reproduced tests.

MCPWarden continues forwarding arguments unchanged. It should not silently delete nulls or retry arbitrary calls. The earlier fix preserving the upstream session after request decoding errors addresses a different issue; these responses are tool-level errors, not connection loss.

This is a local draft report. No issue was submitted externally.
