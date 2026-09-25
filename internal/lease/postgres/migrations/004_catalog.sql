-- Gateway catalog and indexed history (roadmap step 3). Every secret-bearing
-- value (headers, OAuth grants and client secrets, password salts and hashes,
-- access-token verifiers, cached tool schemas) is inside `sealed`: AES-GCM
-- ciphertext made by the gateway with its existing catalog key before the value
-- reaches PostgreSQL. This is legacy server-managed custody, not client
-- encryption; the plain columns exist for constraints, indexes and locking.

-- One row describes which store is authoritative. Only the migration role
-- changes it; the runtime role can only read it.
CREATE TABLE mcpwarden_security.catalog_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    state text NOT NULL CHECK (state IN ('importing','imported','aborting','active','rolling_back','rolled_back')),
    import_id uuid NOT NULL,
    source_catalog_sha256 text NOT NULL CHECK (length(source_catalog_sha256) = 64),
    source_history_sha256 text NOT NULL CHECK (length(source_history_sha256) = 64),
    source_history_bytes bigint NOT NULL CHECK (source_history_bytes >= 0),
    history_lines bigint NOT NULL DEFAULT 0 CHECK (history_lines >= 0),
    history_bytes bigint NOT NULL DEFAULT 0 CHECK (history_bytes >= 0),
    history_sha256_state bytea,
    manifest jsonb CHECK (manifest IS NULL OR jsonb_typeof(manifest) = 'object'),
    rollback_id uuid,
    rollback_manifest jsonb CHECK (rollback_manifest IS NULL OR jsonb_typeof(rollback_manifest) = 'object'),
    -- Import start; also the time used to end MCP sessions left open in the file.
    started_at timestamptz NOT NULL,
    changed_at timestamptz NOT NULL,
    CHECK (state IN ('importing','aborting') OR manifest IS NOT NULL),
    CHECK ((state IN ('rolling_back','rolled_back')) = (rollback_id IS NOT NULL)),
    CHECK (state <> 'rolled_back' OR rollback_manifest IS NOT NULL)
);

CREATE TABLE mcpwarden_security.catalog_accounts (
    owner_id text PRIMARY KEY REFERENCES mcpwarden_security.owners(owner_id),
    username text NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 200),
    created_at timestamptz,
    updated_at timestamptz,
    sealed bytea NOT NULL
);

CREATE TABLE mcpwarden_security.catalog_access (
    access_id text PRIMARY KEY CHECK (length(access_id) BETWEEN 1 AND 200),
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    public_id text UNIQUE,
    -- HMAC of the stored token verifier under a key derived from the catalog key.
    secret_digest bytea NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    kind text NOT NULL CHECK (kind IN ('api_key','browser','oauth','mcp')),
    role text NOT NULL CHECK (role IN ('admin','client')),
    created_at timestamptz,
    updated_at timestamptz,
    last_used_at timestamptz,
    expires_at timestamptz,
    ended_at timestamptz,
    revoked_at timestamptz,
    deleted_at timestamptz,
    sealed bytea NOT NULL
);
CREATE INDEX catalog_access_owner ON mcpwarden_security.catalog_access(owner_id, kind);

-- A deleted connector keeps its row as a credential-free tombstone whose sealed
-- payload is only its lifecycle.
CREATE TABLE mcpwarden_security.catalog_connectors (
    connector_id uuid PRIMARY KEY,
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    name text CHECK (name ~ '^[a-z0-9-]{1,20}$'),
    auth_type text NOT NULL CHECK (auth_type IN ('','none','headers','bearer','api_key','oauth')),
    custody text NOT NULL DEFAULT 'legacy_managed' CHECK (custody = 'legacy_managed'),
    grant_id text,
    grant_revision bigint NOT NULL DEFAULT 0 CHECK (grant_revision >= 0),
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz,
    sealed bytea NOT NULL,
    CHECK ((deleted_at IS NULL) = (name IS NOT NULL)),
    CHECK (deleted_at IS NULL OR grant_id IS NULL)
);
CREATE UNIQUE INDEX catalog_connectors_owner_name ON mcpwarden_security.catalog_connectors(owner_id, name) WHERE deleted_at IS NULL;

-- File-catalog tombstones never recorded their owner.
CREATE TABLE mcpwarden_security.catalog_legacy_tombstones (
    connector_id uuid PRIMARY KEY,
    deleted_at timestamptz NOT NULL,
    sealed bytea NOT NULL
);

-- Discovery and visibility are keyed by provider name, like the file catalog:
-- configured (static) upstreams have them too.
CREATE TABLE mcpwarden_security.catalog_discovery (
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    updated_at timestamptz,
    sealed bytea NOT NULL,
    PRIMARY KEY (owner_id, provider)
);

CREATE TABLE mcpwarden_security.catalog_visibility (
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    mode text NOT NULL CHECK (mode IN ('all','selected')),
    disabled boolean NOT NULL,
    created_at timestamptz,
    updated_at timestamptz,
    sealed bytea NOT NULL,
    PRIMARY KEY (owner_id, provider)
);

-- Append-only tool-call history. `record` holds the exact JSON bytes: the
-- original JSONL line for imported rows, the writer's encoding for live rows.
-- Rows are never deleted with connectors or accounts.
CREATE TABLE mcpwarden_security.history_events (
    seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id text NOT NULL,
    event_id text NOT NULL CHECK (length(event_id) BETWEEN 1 AND 200),
    schema_version smallint NOT NULL CHECK (schema_version BETWEEN 0 AND 2),
    event_type text CHECK (event_type IN ('tool.dispatch.admitted','tool.dispatch.completed','tool.dispatch.denied')),
    invocation_id text,
    tool_id text NOT NULL,
    tool text NOT NULL,
    upstream text NOT NULL,
    status text NOT NULL,
    actor_access_id text NOT NULL,
    -- Unix nanoseconds, so filters and ordering match the JSONL reader exactly.
    ts_ns bigint NOT NULL,
    history_ns bigint NOT NULL,
    -- Timing for performance summaries; buckets use the reader's log2 scale.
    timed boolean NOT NULL,
    failed boolean NOT NULL,
    forwarded boolean NOT NULL,
    handler_us bigint NOT NULL,
    gateway_us bigint NOT NULL,
    upstream_us bigint NOT NULL,
    handler_bucket smallint NOT NULL CHECK (handler_bucket BETWEEN 0 AND 31),
    gateway_bucket smallint NOT NULL CHECK (gateway_bucket BETWEEN 0 AND 31),
    upstream_bucket smallint NOT NULL CHECK (upstream_bucket BETWEEN 0 AND 31),
    record text NOT NULL,
    source text NOT NULL CHECK (source IN ('legacy','live')),
    source_line bigint CHECK (source_line > 0),
    CHECK ((source = 'legacy') = (source_line IS NOT NULL)),
    CHECK ((schema_version = 2) = (event_type IS NOT NULL AND invocation_id IS NOT NULL)),
    UNIQUE (owner_id, event_id),
    UNIQUE (owner_id, invocation_id, event_type)
);
CREATE UNIQUE INDEX history_events_source_line ON mcpwarden_security.history_events(source_line) WHERE source = 'legacy';
CREATE INDEX history_owner_recent ON mcpwarden_security.history_events(owner_id, history_ns DESC, event_id COLLATE "C" DESC);
CREATE INDEX history_owner_tool ON mcpwarden_security.history_events(owner_id, tool_id, ts_ns);
CREATE INDEX history_owner_upstream ON mcpwarden_security.history_events(owner_id, upstream, ts_ns);
CREATE INDEX history_owner_invocation ON mcpwarden_security.history_events(owner_id, invocation_id) WHERE invocation_id IS NOT NULL;

ALTER TABLE mcpwarden_security.security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE mcpwarden_security.security_events ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
    'request.created','request.confirmed','request.denied','request.expired','request.stale',
    'lease.activated','lease.expired','lease.revoked','lease.suspended',
    'vault.created','vault.rewrapped','credential.created','credential.updated','credential.rotated','credential.deleted',
    'policy.changed','activation.rejected','execution.locked','owner_route.rejected',
    'account.created','account.password_changed','access.created','access.revoked','access.renamed','access.ended',
    'connector.created','connector.deleted','connector.oauth_saved','connector.visibility_changed','connector.availability_changed'));

REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcpwarden_security FROM PUBLIC;
