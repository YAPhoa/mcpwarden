-- mcpwarden client-release security model: CANDIDATE schema, 2026-09-22.
-- For review / an EMPTY SCRATCH DATABASE only. This is not a project migration.
-- No PostgreSQL server was available while preparing this bundle: NOT EXECUTED.
-- UUIDs are supplied by the application; no UUID/crypto extension is required.
-- No plaintext provider secrets, VRKs, recovery keys, CEKs or raw tool payloads.
-- Application authorization and immutable-scope validation remain mandatory.
-- Runtime, schema-owner and audit-retention privileges must be separate.
-- CREATE SCHEMA intentionally has no IF NOT EXISTS: do not silently reuse one.

BEGIN;
CREATE SCHEMA mcpwarden_spec;
SET LOCAL search_path = mcpwarden_spec, pg_catalog;

CREATE TABLE owners (
    owner_id text PRIMARY KEY,
    auth_mode text NOT NULL CHECK (auth_mode IN ('local_operator','local_accounts','external_oauth')),
    issuer text,
    external_subject text,
    security_revision bigint NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    disabled_at timestamptz,
    CHECK (length(owner_id) BETWEEN 1 AND 512),
    CHECK (auth_mode <> 'external_oauth' OR (issuer IS NOT NULL AND external_subject IS NOT NULL)),
    UNIQUE (issuer, external_subject)
);

CREATE TABLE local_account_verifiers (
    owner_id text PRIMARY KEY REFERENCES owners(owner_id),
    login_name text NOT NULL UNIQUE,
    algorithm text NOT NULL,
    salt bytea NOT NULL CHECK (octet_length(salt) >= 16),
    verifier bytea NOT NULL CHECK (octet_length(verifier) >= 32),
    parameters jsonb NOT NULL CHECK (jsonb_typeof(parameters) = 'object'),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
    -- Preserve existing PBKDF2 verifiers/parameters during import.
    -- No column is a reversibly encrypted login password.
);

CREATE TABLE access_records (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    access_id uuid NOT NULL,
    record_kind text NOT NULL CHECK (record_kind IN ('api_key','browser_session','external_oauth','local_operator')),
    public_id text NOT NULL,
    label text NOT NULL,
    role text NOT NULL CHECK (role IN ('client','admin','interactive_owner')),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (owner_id, access_id),
    UNIQUE (public_id),
    UNIQUE (token_sha256),
    CHECK (length(public_id) BETWEEN 1 AND 128),
    CHECK (length(label) BETWEEN 1 AND 200),
    CHECK (expires_at > created_at),
    CHECK (role <> 'interactive_owner' OR record_kind IN ('browser_session','external_oauth'))
    -- Do not expose interactive_owner as a role mintable by ordinary API keys.
    -- Count/check owner caps under the owner row lock in the same transaction.
);
CREATE INDEX access_records_owner_live ON access_records(owner_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE connectors (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    connector_id uuid NOT NULL,
    name text NOT NULL,
    transport text NOT NULL CHECK (transport IN ('http','stdio')),
    auth_kind text NOT NULL CHECK (auth_kind IN ('none','headers','oauth')),
    custody_mode text NOT NULL CHECK (custody_mode IN ('none','client_release')),
    endpoint text,
    public_transport_config jsonb NOT NULL DEFAULT '{}'::jsonb,
    destination_profile jsonb NOT NULL,
    destination_sha256 bytea NOT NULL CHECK (octet_length(destination_sha256) = 32),
    security_revision bigint NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    PRIMARY KEY (owner_id, connector_id),
    CHECK (jsonb_typeof(public_transport_config) = 'object'),
    CHECK (jsonb_typeof(destination_profile) = 'object'),
    CHECK ((auth_kind = 'none' AND custody_mode = 'none') OR
           (auth_kind <> 'none' AND custody_mode = 'client_release')),
    CHECK (length(name) BETWEEN 1 AND 200),
    CHECK (transport <> 'http' OR endpoint IS NOT NULL)
    -- Only safe metadata: no private environment values, token query strings,
    -- client secrets, or custom credential-header values in these JSON columns.
    -- Legacy server-managed imports require a SEPARATE transitional adapter.
);
CREATE UNIQUE INDEX connectors_live_name ON connectors(owner_id, name) WHERE deleted_at IS NULL;

CREATE TABLE vault_roots (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    root_id uuid NOT NULL,
    root_version bigint NOT NULL CHECK (root_version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (owner_id, root_id),
    UNIQUE (owner_id, root_version)
    -- Root identity only. Never store root plaintext here.
);

CREATE TABLE root_wrappers (
    owner_id text NOT NULL,
    wrapper_id uuid NOT NULL,
    root_id uuid NOT NULL,
    method text NOT NULL CHECK (method IN ('passphrase','recovery')),
    envelope_format text NOT NULL CHECK (envelope_format = 'mcpwarden.root-wrap.v1'),
    algorithm text NOT NULL CHECK (algorithm = 'AES-256-GCM'),
    public_kdf_metadata jsonb NOT NULL CHECK (jsonb_typeof(public_kdf_metadata) = 'object'),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext_and_tag bytea NOT NULL CHECK (octet_length(ciphertext_and_tag) = 48),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (owner_id, wrapper_id),
    FOREIGN KEY (owner_id, root_id) REFERENCES vault_roots(owner_id, root_id)
    -- AAD is reconstructed from the exact, validated wrapper metadata.
    -- Recovery key and passphrase/KDF output are never persisted.
);

CREATE TABLE credentials (
    owner_id text NOT NULL,
    credential_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    label text NOT NULL,
    current_epoch bigint NOT NULL CHECK (current_epoch > 0),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (owner_id, credential_id),
    UNIQUE (owner_id, credential_id, connector_id),
    FOREIGN KEY (owner_id, connector_id) REFERENCES connectors(owner_id, connector_id)
    -- Current-version FK added after the version table; deferred for insertion.
);
CREATE UNIQUE INDEX one_current_credential_per_connector
    ON credentials(owner_id, connector_id) WHERE retired_at IS NULL;

CREATE TABLE credential_epochs (
    owner_id text NOT NULL,
    credential_id uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    root_id uuid NOT NULL,
    destination_sha256 bytea NOT NULL CHECK (octet_length(destination_sha256) = 32),
    wrapper_format text NOT NULL CHECK (wrapper_format = 'mcpwarden.credential-wrap.v1'),
    wrapper_nonce bytea NOT NULL CHECK (octet_length(wrapper_nonce) = 12),
    wrapped_cek_and_tag bytea NOT NULL CHECK (octet_length(wrapped_cek_and_tag) = 48),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (owner_id, credential_id, epoch),
    FOREIGN KEY (owner_id, credential_id) REFERENCES credentials(owner_id, credential_id),
    FOREIGN KEY (owner_id, root_id) REFERENCES vault_roots(owner_id, root_id)
    -- root_id identifies the CLIENT root wrapping this CEK; no server wrapper.
    -- Rewrapping under a new root uses a new random wrapper_nonce, atomically.
);

CREATE TABLE credential_versions (
    owner_id text NOT NULL,
    credential_id uuid NOT NULL,
    epoch bigint NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    envelope_format text NOT NULL CHECK (envelope_format = 'mcpwarden.secret.v1'),
    algorithm text NOT NULL CHECK (algorithm = 'AES-256-GCM'),
    purpose text NOT NULL CHECK (purpose = 'upstream-credential'),
    destination_sha256 bytea NOT NULL CHECK (octet_length(destination_sha256) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext_and_tag bytea NOT NULL CHECK (octet_length(ciphertext_and_tag) >= 16),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, credential_id, epoch, revision),
    UNIQUE (owner_id, credential_id, epoch, nonce),
    FOREIGN KEY (owner_id, credential_id, epoch)
        REFERENCES credential_epochs(owner_id, credential_id, epoch)
    -- Ciphertext is the complete secret bundle (including OAuth tokens).
    -- Unique nonce catches a collision while rows remain; RNG remains mandatory.
);
ALTER TABLE credentials ADD CONSTRAINT credential_current_version_fk
    FOREIGN KEY (owner_id, credential_id, current_epoch, current_revision)
    REFERENCES credential_versions(owner_id, credential_id, epoch, revision)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE tool_definitions (
    owner_id text NOT NULL,
    tool_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    upstream_name text NOT NULL,
    public_definition jsonb NOT NULL CHECK (jsonb_typeof(public_definition) = 'object'),
    definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
    visible boolean NOT NULL DEFAULT false,
    refreshed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz,
    PRIMARY KEY (owner_id, tool_id),
    UNIQUE (owner_id, connector_id, upstream_name),
    FOREIGN KEY (owner_id, connector_id) REFERENCES connectors(owner_id, connector_id)
    -- Names/descriptions/schemas are untrusted text, not proof of read-only safety.
);

CREATE TABLE oauth_grants (
    owner_id text NOT NULL,
    grant_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    credential_epoch bigint NOT NULL,
    credential_revision bigint NOT NULL,
    issuer text NOT NULL,
    resource text NOT NULL,
    public_client_id text,
    approved_scopes jsonb NOT NULL CHECK (jsonb_typeof(approved_scopes) = 'array'),
    state text NOT NULL CHECK (state IN ('ready','reauthorization_required','revoked')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, grant_id),
    UNIQUE (owner_id, credential_id),
    FOREIGN KEY (owner_id, credential_id, credential_epoch, credential_revision)
        REFERENCES credential_versions(owner_id, credential_id, epoch, revision)
    -- NO access_token, refresh_token or client_secret columns.
    -- Single-flight BEFORE provider refresh plus CAS on epoch/revision afterwards.
);

CREATE TABLE approval_requests (
    owner_id text NOT NULL,
    approval_id uuid NOT NULL,
    requester_access_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    credential_epoch bigint NOT NULL,
    gateway_boot_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('tool_use','setup_discovery','oauth_setup')),
    approval_mode text NOT NULL CHECK (approval_mode IN ('none','confirm','step_up')),
    approval_policy_revision bigint NOT NULL CHECK (approval_policy_revision > 0),
    verification_method text NOT NULL,
    authorization_source text CHECK (authorization_source IN
        ('client_activation','owner_confirmation','step_up')),
    scope jsonb NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    scope_sha256 bytea NOT NULL CHECK (octet_length(scope_sha256) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    request_nonce bytea NOT NULL CHECK (octet_length(request_nonce) = 32),
    requested_ttl_seconds integer NOT NULL CHECK (requested_ttl_seconds > 0),
    max_calls bigint CHECK (max_calls > 0),
    state text NOT NULL CHECK (state IN ('pending','challenging','approved','activated','denied','expired','cancelled','stale')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    decided_at timestamptz,
    activation_deadline timestamptz,
    approving_access_id uuid,
    approving_owner_id text,
    PRIMARY KEY (owner_id, approval_id),
    FOREIGN KEY (owner_id, requester_access_id) REFERENCES access_records(owner_id, access_id),
    FOREIGN KEY (owner_id, connector_id) REFERENCES connectors(owner_id, connector_id),
    FOREIGN KEY (owner_id, credential_id, connector_id)
        REFERENCES credentials(owner_id, credential_id, connector_id),
    FOREIGN KEY (owner_id, credential_id, credential_epoch)
        REFERENCES credential_epochs(owner_id, credential_id, epoch),
    FOREIGN KEY (owner_id, approving_access_id) REFERENCES access_records(owner_id, access_id),
    FOREIGN KEY (approving_owner_id) REFERENCES owners(owner_id),
    CHECK (approving_owner_id IS NULL OR approving_owner_id = owner_id),
    CHECK ((approval_mode = 'step_up' AND verification_method <> 'none') OR
           (approval_mode IN ('none','confirm') AND verification_method = 'none')),
    CHECK (authorization_source IS NULL OR
           (approval_mode = 'none' AND authorization_source = 'client_activation') OR
           (approval_mode = 'confirm' AND authorization_source = 'owner_confirmation') OR
           (approval_mode = 'step_up' AND authorization_source = 'step_up')),
    CHECK (expires_at > created_at),
    CHECK (activation_deadline IS NULL OR activation_deadline <= expires_at),
    CHECK (state NOT IN ('approved','activated') OR
           (authorization_source IS NOT NULL AND decided_at IS NOT NULL AND activation_deadline IS NOT NULL AND approving_access_id IS NOT NULL AND approving_owner_id IS NOT NULL)),
    UNIQUE (owner_id, approval_id, requester_access_id, credential_id, credential_epoch, gateway_boot_id, scope_sha256)
    -- Binding columns are immutable after creation, enforced by a narrow service
    -- update API / optional database trigger, NOT this JSON CHECK alone.
    -- Policy TTL cap, canonical digest and current security revisions are checked
    -- under the coordinator and transaction immediately before activation.
);
CREATE UNIQUE INDEX approval_requests_live_equivalent
    ON approval_requests(owner_id, requester_access_id, credential_id, credential_epoch, gateway_boot_id, scope_sha256)
    WHERE state IN ('pending','challenging','approved');
-- Expire stale requests explicitly before inserting an equivalent request;
-- a partial-index predicate cannot be a moving wall-clock test.

CREATE TABLE approval_attempts (
    owner_id text NOT NULL,
    attempt_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    provider text NOT NULL, -- Application registry allowlist, not a vendor enum.
    verification_method text NOT NULL CHECK (verification_method <> 'none'),
    factor_id uuid, -- Optional module supplies composite FK once enrolled.
    approval_policy_revision bigint NOT NULL CHECK (approval_policy_revision > 0),
    provider_transaction_id text,
    approving_access_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('created','pending','approved','denied','expired','error')),
    result_code text,
    fresh_verification boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (owner_id, attempt_id),
    FOREIGN KEY (owner_id, approval_id) REFERENCES approval_requests(owner_id, approval_id),
    FOREIGN KEY (owner_id, approving_access_id) REFERENCES access_records(owner_id, access_id),
    CHECK (expires_at > created_at),
    CHECK (state <> 'approved' OR completed_at IS NOT NULL)
    -- No factor seed, OTP/verification code, raw response or full push payload.
    -- No successful attempt is fabricated for none/confirm without a factor.
    -- result_code is an application allowlist, not arbitrary provider error text.
);
CREATE UNIQUE INDEX approval_attempt_provider_txid
    ON approval_attempts(provider, provider_transaction_id)
    WHERE provider_transaction_id IS NOT NULL;

CREATE TABLE execution_leases (
    owner_id text NOT NULL,
    lease_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    requester_access_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    credential_epoch bigint NOT NULL,
    gateway_boot_id uuid NOT NULL,
    scope_sha256 bytea NOT NULL CHECK (octet_length(scope_sha256) = 32),
    state text NOT NULL CHECK (state IN ('active','expired','revoked','suspended','superseded')),
    activated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ended_at timestamptz,
    max_calls bigint CHECK (max_calls > 0),
    admitted_calls bigint NOT NULL DEFAULT 0 CHECK (admitted_calls >= 0),
    PRIMARY KEY (owner_id, lease_id),
    UNIQUE (owner_id, approval_id),
    FOREIGN KEY (owner_id, approval_id, requester_access_id, credential_id, credential_epoch, gateway_boot_id, scope_sha256)
        REFERENCES approval_requests(owner_id, approval_id, requester_access_id, credential_id, credential_epoch, gateway_boot_id, scope_sha256),
    CHECK (expires_at > activated_at),
    CHECK (max_calls IS NULL OR admitted_calls <= max_calls)
    -- Active record != memory activation. No unwrapped key is stored here.
    -- Compare binding/scope/max_calls/expiry to immutable approval in service code.
);
CREATE INDEX execution_leases_lookup
    ON execution_leases(owner_id, requester_access_id, credential_id, credential_epoch, expires_at)
    WHERE state = 'active';

CREATE TABLE audit_events (
    owner_id text NOT NULL REFERENCES owners(owner_id),
    event_id uuid NOT NULL,
    event_sequence bigint GENERATED ALWAYS AS IDENTITY,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    event_type text NOT NULL,
    invocation_id uuid,
    client_access_id uuid,
    client_public_id text,
    client_label_snapshot text,
    connector_id uuid,
    connector_name_snapshot text,
    credential_id uuid,
    credential_epoch bigint,
    credential_revision bigint,
    tool_id uuid,
    tool_name_snapshot text,
    approval_id uuid,
    lease_id uuid,
    approving_owner_id text,
    approval_mode text CHECK (approval_mode IN ('none','confirm','step_up')),
    approval_policy_revision bigint,
    authorization_source text CHECK (authorization_source IN
        ('client_activation','owner_confirmation','step_up')),
    verification_method text,
    decision text CHECK (decision IN ('allow','deny','not_applicable')),
    result text,
    error_code text,
    argument_hash_version text,
    arguments_sha256 bytea CHECK (arguments_sha256 IS NULL OR octet_length(arguments_sha256) = 32),
    duration_ms bigint CHECK (duration_ms >= 0),
    response_item_count integer CHECK (response_item_count >= 0),
    structured_response_present boolean,
    PRIMARY KEY (owner_id, event_id),
    UNIQUE (event_sequence),
    CHECK ((arguments_sha256 IS NULL) = (argument_hash_version IS NULL))
    -- No FKs to deletable client/connector/credential/tool/lease rows: snapshots
    -- and identifiers survive cleanup. No cascading history deletion.
    -- Add any existing timing/session-hash fields needed by the actual audit
    -- contract before migration; this is a TARGET SECURITY schema, not a claim
    -- that all current application columns have been reverse-engineered.
);
CREATE INDEX audit_events_owner_order ON audit_events(owner_id, occurred_at, event_sequence);
CREATE INDEX audit_events_actor ON audit_events(owner_id, client_access_id, occurred_at);
CREATE INDEX audit_events_lease ON audit_events(owner_id, lease_id, occurred_at);
CREATE INDEX audit_events_invocation ON audit_events(owner_id, invocation_id);

-- Operational role plan (NOT automatically applied here):
-- * schema migration role owns schema/tables and runs reviewed migrations.
-- * runtime role gets only necessary table privileges; audit INSERT + SELECT,
--   never audit UPDATE/DELETE/TRUNCATE or schema CREATE.
-- * separate retention role may remove aged audit rows under explicit policy.
-- * owner filtering is mandatory in code. Optional RLS needs complete policies,
--   transaction-local owner context, tests, and review of BYPASSRLS/table ownership.
-- * service code controls state transitions and immutable approval binding fields.
-- * no generic untrusted JSON/raw errors may be copied into any metadata column.
-- * purge dependencies in a reviewed order (approvals/leasing cleanup, grant,
--   pointers, versions/epochs) while preserving audit. Tombstone connector first.
-- * production migration must add the current catalog/audit contract's remaining
--   fields, transient OAuth browser-flow store, and cap/lifecycle semantics.

COMMIT;
