# Optional approval, push notifications, and OTP

**mcpwarden security specification v1.1 — 22 September 2026.** Proposed functionality, not implemented features. This supersedes the vendor-centric v1.0 approval requirements. The full design is [SECURITY-DESIGN.md](SECURITY-DESIGN.md); references are [REFERENCES.md](REFERENCES.md).

## 11. Optional approval, notifications, and verification

### 11.1 Product controls and supported combinations

**No external approval vendor is required.** First-party in-app review is the baseline. Three independent decisions determine behavior:

| Control | Values | Meaning |
|---|---|---|
| `approvals.mode` | `none`, `confirm`, `step_up` | No extra approval; explicit owner confirmation; or confirmation with an enrolled factor. |
| `approvals.verification.method` | `none`, `totp`, optionally `webauthn` or a reviewed device adapter | How additional verification is proven. A method must be implemented and enrolled before it is selectable. |
| `notifications.web_push.enabled` | `false`, `true` | Whether to deliver first-party browser/app review notifications. It does not choose or satisfy a verification method. |

Proposed baseline: `mode: confirm`, `verification.method: none`, Web Push off. The owner may select `none` to remove the extra confirmation entirely. A local authenticator OTP flow needs no push service. Push-assisted confirmation needs no OTP. Combining push delivery with OTP is also valid.

For the simple UI, expose **Require approval before access**, **Require additional verification**, and **Send push notifications**. Map these to the enum, not three independently trusted booleans from an MCP caller. When approval is off, factor verification for lease creation is off too; login MFA is a separate account setting and must not be disabled as a side effect.

A notification or a button in an already logged-in page is not automatically a second authentication factor. Call that mode “confirmation.” Only label it additional verification when the required enrolled factor actually succeeds. [R40]

### 11.2 Exact behavior when extra approval is disabled

`mode: none` means **no additional confirmation or OTP/push challenge**, not “no authorization.” In this client-release design, the owner still starts a bounded window in an authenticated key-holding client. That action can combine scope selection, key release, and activation without a separate Approve dialog.

1. The named MCP client may create an immutable request for its own permitted scope. This never authorizes execution.
2. The owner starts access in the UI. Authenticate that owner, validate CSRF/origin, resolve the server's effective policy, and validate the selected credential/key exactly as in §7.5.
3. Under the owner coordinator and transaction, require a live `pending` request, current boot/revisions, and `approval_mode=none`; bind the activating owner. Record `authorization_source=client_activation`, then create the fixed-duration lease and runtime activation. No `approval_attempts` success is fabricated.
4. Every MCP call still checks that particular caller's lease and runtime credential. The client never receives an unwrapped credential or activation authority.
5. After expiry or restart, a new owner-initiated window is required. A live CEK for caller A is not permission to mint a lease for caller B. Agent traffic must not silently renew a window.

This retains the original timed-window requirement. Fully unattended automatic renewal, permanent activation, or server-managed custody is a different explicit product policy; it is not inferred from turning notifications or extra approval off.

### 11.3 Separate interfaces, not a vendor-shaped core

Proposed domain sketches, not existing symbols:

```go
type NotificationSender interface {
    // Delivery cannot return an approval decision.
    Notify(ctx context.Context, target EnrolledNotificationTarget,
        notice SafeApprovalNotice) error
}

type VerificationMethod interface {
    // Challenge/proof DTOs are tagged and method-specific, with bounded sizes.
    Begin(ctx context.Context, binding ApprovalBinding) (ChallengeView, error)
    Verify(ctx context.Context, binding ApprovalBinding,
        proof VerificationProof) (VerificationEvidence, error)
}
```

The authorization service owns effective policy, immutable scope/request digests, deadlines, state transitions, and activation. `ApprovalBinding` includes owner, requester, credential epoch, boot, challenge, `approval_mode`, verification requirement, and approval-policy revision. Add those mode/revision fields to `request_digest`; the browser cannot change them after review. Strictly bind verification evidence to that request and the enrolled owner factor. Do not accept `approved: true`, a delivery receipt, or an arbitrary provider result from the browser as authority.

`none` invokes no verifier; `confirm` uses authenticated owner confirmation; `step_up` invokes the selected verifier once for that new window. The hot `tools/call` path invokes neither interface when the lease is valid. A future asynchronous external adapter can poll internally; polling is not a mandatory operation for all verification methods.

### 11.4 First-party in-app and browser push approval

**Implementation proposal:** ship an owner-scoped pending-request inbox using authenticated polling or SSE before requiring background notification support. The same review/decision endpoints work whether the user arrived through the sidebar, a notification, or a second enrolled browser.

Optional Web Push uses a service worker and `PushManager.subscribe` after an explicit notification permission gesture. The Push API supplies delivery to a web application, not human authorization. Feature-test target clients; do not promise background delivery merely because the page uses HTTPS. [R35]

Use the standard Web Push protocol for delivery, its payload encryption, and VAPID for application-server identification. VAPID identifies the sender to the push service; it does not authenticate the approving person. Prefer a maintained implementation over custom protocol cryptography. [R36–R38]

Proposed processing steps:

1. Authenticate enrollment. Store the owner/device association and encrypted subscription endpoint, `p256dh`, and `auth` material separately from vault credential encryption. A subscription is a delivery record, not a factor enrollment or vault recipient. Keep the VAPID private key in an operational secret store outside the database dump's trust boundary.
2. Treat a submitted endpoint as untrusted outbound input: require HTTPS, constrain approved push-service destinations, reject local/metadata/private destinations, revalidate DNS at connection time, and reject redirects. Never send vault credentials on this transport. See §16 and [R34].
3. Persist the access request before sending. Send only an opaque request identifier and generic text such as “An access request needs your review.” No token, key, OTP, raw arguments, credential label, or privileged approval URL is needed in the payload. Delivery TTL must not outlast request expiry.
4. A notification click opens a fixed same-origin path. The page authenticates the owner, retrieves current request details, and displays the actual caller/scope/duration. A URL is navigation, never a bearer approval capability; a GET cannot approve.
5. Confirmation uses a CSRF-protected POST. If `step_up` is configured, verify the enrolled factor before transitioning the request. Key release remains the distinct activation step; receipt or dismissal of a notification changes no permission.
6. Deduplicate equivalent requests and apply per-owner, per-client, and per-device limits plus an explicit resend cooldown. A notification delivery retry must not create a new approval, extend its expiry, or execute a tool. Drop expired/revoked subscriptions and stop retries at the local request deadline.

Browser push may involve a browser-selected external delivery service. Do not equate a self-hosted mcpwarden gateway with a fully self-hosted push network. Where external delivery is undesirable or unsupported, retain the in-app inbox. See the service role defined in [R35, R36].

A real enrolled phone/browser that also holds vault material may perform both approval and key release. An ordinary push service or authenticator app has no such material by default. No requirement to build a native mobile vault is introduced by this revision.

### 11.5 Optional authenticator OTP

For the OTP option, the initial proposal is local **TOTP** verification, rather than email/SMS codes or a mandatory cloud provider. RFC 6238 defines the time-based shared-secret construction, test vectors, bounded clock-skew handling, and rejection of reuse after successful validation. It does not bind an OTP to a tool scope or transaction by itself. [R39]

Proposed implementation requirements:

- Enroll only through fresh owner authentication; require a valid first code before activating the factor. Existing-factor replacement follows §17.5. Do not expose enrollment material through ordinary management/history APIs.
- Store each seed encrypted under a **separate operational factor-storage key**, not as a hash and not under the client CEK whose release depends on that factor. The verifier needs the seed or equivalent secure verification capability. This server-decryptable factor seed is not a server wrapper for the vault root or provider credentials; document that distinct custody boundary.
- Create a short-lived attempt bound to the request digest, enrolled factor, owner session, required method, and approval-policy revision. Verify inside the authenticated review flow; do not accept codes submitted by the MCP agent.
- Validate a deliberately small clock window and rate-limit by factor, owner, and attempt. Atomically consume the successful factor/time-step so concurrent requests cannot reuse a code. Share replay state with login verification if the same enrolled seed is used there. Keep no raw codes, seed values, enrollment QR data, or request bodies in logs.
- In the same transaction, record verified evidence for exactly that request. A cached `mfa_verified=true` flag on an account must not authorize unrelated new windows. Duplicates return the existing decision rather than granting another lease.
- Requiring a new code applies to starting/renewing a window, not to every MCP invocation. TOTP must not be described as a scope signature, vault decryption key, or phishing-resistant proof. [R39, R40]

The cryptographic validation of TOTP is standard; transaction binding, replay storage, mode selection, and lease behavior above are mcpwarden design decisions. The optional SQL companion gives storage sketches, not a tested factor implementation.

### 11.6 Enabling, disabling, and policy precedence

Keep delivery preferences separate from security policy. Turning Web Push off only stops notifications; pending requests remain visible in-app and required OTP still applies. Disabling a required factor or changing `step_up` to a weaker mode requires fresh owner authentication and the existing factor, or a deliberately enrolled recovery procedure. Never let an ordinary client/admin MCP key perform that change. [R40]

Proposed initial policy granularity is an owner default. An optional connector override can only tighten it (`none < confirm < step_up`); lower-level settings cannot weaken an operator-enforced minimum. Verification methods are not automatically interchangeable: require the configured method or an explicitly enrolled allowed alternative. A named client cannot choose a weaker mode in its access request.

For changes to approval requirements, increment an approval-policy revision, invalidate pending attempts and unactivated decisions under the prior revision, and revoke affected active leases under the same owner coordinator before reporting success. This conservative initial rule applies to both tightening and weakening, so a toggle cannot silently reinterpret an existing window. A delivery-only preference change does not revoke active leases.

Preserve `authorization_source` and policy revision in history. Turning extra approval off is an explicit security decision, not a reason to stop logging which client key used which credential.

### 11.7 Failure and fallback behavior

Push unavailable or permission denied: the same policy can still be satisfied through the authenticated inbox, because delivery is not verification. Required TOTP/WebAuthn unavailable: fail closed for new windows unless an allowed alternative was explicitly enrolled in advance. Do not silently downgrade to `none`, email, SMS, or ordinary confirmation. Existing leases retain their original deadline unless revoked by a security-policy change. Local revocation/execution lock does not depend on notification delivery or factor availability.

All notifications and verification outcomes are stale after their request expires, its policy revision changes, its caller is revoked, or the gateway restarts. A notification that arrives late opens a current status view, not an approval action.

### 11.8 External adapters are optional future integrations

Duo is only an example of a possible adapter, not a required provider, package, configuration block, milestone, or deployment prerequisite. Legacy references R11–R13 are retained for traceability only. No external adapter is needed to ship `none`, first-party `confirm`, or local TOTP. An adapter added later must meet the same immutable-request, fresh-evidence, replay, outage, and logging requirements; it cannot change the lease or key hierarchy.

WebAuthn may later provide additional verification. Its PRF extension is a separate possible vault-unlock mechanism; ordinary authentication does not derive the vault root. Prevent client-only PRF output from leaking in serialized authentication responses. [R30]


## Configuration

See [approval-config.yaml](reference/approval-config.yaml). Use `confirm` plus `method: none` for in-app review, `none` plus `method: none` to skip extra review, or `step_up` plus an implemented/enrolled `totp` method for OTP once per window. Web Push is independently optional.
