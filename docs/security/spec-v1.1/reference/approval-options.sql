-- OPTIONAL candidate storage extension to reference/schema.sql, design v1.1.
-- Apply only in an empty review database after the base candidate schema.
-- NOT an executed migration, production patch, or complete enrollment protocol.
-- Unused push/TOTP options must not require operational keys or connectivity.
BEGIN;

-- Operator-only configuration can precede this table. This is the proposed
-- durable source for owner-editable defaults. No caller-supplied weakening.
CREATE TABLE owner_approval_policies (
    owner_id text PRIMARY KEY REFERENCES owners(owner_id),
    approval_mode text NOT NULL CHECK (approval_mode IN ('none','confirm','step_up')),
    verification_method text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    updated_by_access_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (owner_id, updated_by_access_id)
        REFERENCES access_records(owner_id, access_id),
    CHECK ((approval_mode = 'step_up' AND verification_method <> 'none') OR
           (approval_mode IN ('none','confirm') AND verification_method = 'none'))
    -- Actual implemented/enrolled method is checked in the application registry.
    -- Protected update: owner gate -> owner/policy/access rows -> bindings/leases.
    -- Require fresh owner auth plus existing required factor; increment revision,
    -- stale pending decisions, revoke affected leases, audit, commit, publish.
    -- Notifications on/off must NOT change this revision or security requirement.
);

-- First optional local factor implementation is TOTP. Extending to a passkey or
-- signed-device method needs its own typed public-key metadata, not a fake seed.
CREATE TABLE approval_totp_factors (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    factor_id uuid NOT NULL,
    label text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','active','revoked')),
    factor_revision bigint NOT NULL CHECK (factor_revision > 0),
    algorithm text NOT NULL CHECK (algorithm IN ('SHA1','SHA256','SHA512')),
    digits smallint NOT NULL CHECK (digits IN (6,8)),
    period_seconds integer NOT NULL CHECK (period_seconds > 0),
    envelope_version integer NOT NULL CHECK (envelope_version = 1),
    operational_key_id text NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    encrypted_seed_and_tag bytea NOT NULL CHECK (octet_length(encrypted_seed_and_tag) >= 16),
    last_accepted_step bigint,
    enrollment_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    activated_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (owner_id, factor_id),
    CHECK (state <> 'active' OR activated_at IS NOT NULL),
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL)
    -- Operational key is outside this database, NOT VRK/CEK. Encrypt before SQL.
    -- Reconstruct AAD from envelope version, owner, factor, factor revision,
    -- algorithm/digits/period, and purpose 'totp_seed'; do not trust supplied AAD.
    -- Seed stays encrypted at rest and is never returned after enrollment.
    -- Validate supported parameters/bounds in code, not from row CHECKs alone.
    -- Enroll with first-code verification; use the shared replay state across
    -- login and lease step-up if the same factor is used for both.
);

CREATE TABLE push_subscriptions (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    subscription_id uuid NOT NULL,
    device_label text NOT NULL,
    state text NOT NULL CHECK (state IN ('active','revoked','expired')),
    envelope_version integer NOT NULL CHECK (envelope_version = 1),
    operational_key_id text NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    encrypted_subscription_and_tag bytea NOT NULL CHECK (octet_length(encrypted_subscription_and_tag) >= 16),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (owner_id, subscription_id)
    -- Encrypted payload: endpoint, p256dh, auth. Separate operational storage key.
    -- AAD: version, owner, subscription ID, purpose 'web_push_subscription'.
    -- Recheck permitted destination/DNS/IP/redirect rules before every send.
    -- A subscription has NO factor authority and NO vault key wrapper.
    -- Revocation, permission loss, expired subscription and delivery TTL are
    -- notification lifecycle only, not permission to downgrade verification.
);

-- Illustrative TOTP replay consumption, INSIDE the same owner-coordinated
-- transaction as proof acceptance and the bound approval decision:
-- UPDATE approval_totp_factors
-- SET last_accepted_step = $validated_step
-- WHERE owner_id = $owner AND factor_id = $factor
--   AND state = 'active' AND factor_revision = $expected_revision
--   AND (last_accepted_step IS NULL OR last_accepted_step < $validated_step)
-- RETURNING factor_id;
-- Zero rows rejects acceptance. $validated_step comes ONLY from successful
-- server-side TOTP verification within the allowed window, not browser input.
-- This conservative high-watermark rule rejects earlier steps after accepting
-- a future-skewed code. Do not roll the clock/replay watermark back to fix UX.
-- Record failed-attempt rate limits separately even if decision work rolls back.

-- For a TOTP-only module, bind factor_id in approval_attempts with a validated
-- composite lookup into approval_totp_factors. A generic FK cannot target a union
-- of future factor types; add a shared factor-identity table before adding them.
-- Apply owner predicates and runtime privilege/RLS policy from the base design.
-- Keep operator recovery and one-time recovery-code storage in a separately
-- reviewed enrollment/recovery migration; no weak automatic fallback is implied.
COMMIT;
