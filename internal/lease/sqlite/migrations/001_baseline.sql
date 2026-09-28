-- mcpwarden SQLite baseline: the PostgreSQL schema translated as
-- docs/storage.md describes. Security metadata, ciphertext and sealed catalog
-- records only; no vault root, credential key or plaintext credential.
--
-- Rules: UUIDs are canonical lowercase TEXT; timestamps are INTEGER Unix
-- microseconds (UTC); JSON is TEXT. Guards are BEFORE triggers that
-- RAISE(ABORT), and every comparison on a nullable column is null-safe
-- (IS / IS NOT), because a WHEN or CHECK that is NULL does not fire. Tables are
-- STRICT, so a value of the wrong type is refused rather than coerced.

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE owners (
    owner_id TEXT PRIMARY KEY CHECK (length(owner_id) BETWEEN 1 AND 512)
) STRICT;

-- ---- Access requests and leases ----

CREATE TABLE requests (
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    request_id TEXT NOT NULL CHECK (length(request_id) = 36 AND request_id NOT GLOB '*[^0-9a-f-]*'),
    boot_id TEXT NOT NULL CHECK (length(boot_id) = 36 AND boot_id NOT GLOB '*[^0-9a-f-]*'),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + 300000000),
    binding TEXT NOT NULL CHECK (json_valid(binding) AND json_type(binding) = 'object'
        AND json_extract(binding, '$.id') = request_id
        AND json_extract(binding, '$.boot_id') = boot_id
        AND json_extract(binding, '$.scope.owner_id') = owner_id),
    state TEXT NOT NULL CHECK (state IN ('pending','approved','activated','denied','expired','stale')),
    decided_at INTEGER,
    activation_deadline INTEGER,
    approver_id TEXT CHECK (length(approver_id) = 36 AND approver_id NOT GLOB '*[^0-9a-f-]*'),
    authorization_source TEXT CHECK (authorization_source IN ('client_activation','owner_confirmation')),
    lease_id TEXT CHECK (length(lease_id) = 36 AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    PRIMARY KEY (owner_id, request_id),
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES leases(owner_id, lease_id, request_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK (state <> 'pending' OR (decided_at IS NULL AND activation_deadline IS NULL AND approver_id IS NULL AND authorization_source IS NULL AND lease_id IS NULL)),
    CHECK (state NOT IN ('approved','activated') OR (decided_at IS NOT NULL AND activation_deadline IS NOT NULL AND approver_id IS NOT NULL AND authorization_source IS NOT NULL)),
    CHECK (state <> 'approved' OR (json_extract(binding, '$.mode') = 'confirm' AND authorization_source = 'owner_confirmation' AND lease_id IS NULL)),
    CHECK (state <> 'activated' OR lease_id IS NOT NULL),
    CHECK (activation_deadline IS NULL OR activation_deadline <= expires_at)
) STRICT;
CREATE INDEX requests_owner_recent ON requests(owner_id, created_at);
CREATE INDEX requests_owner_live ON requests(owner_id) WHERE state IN ('pending','approved');

CREATE TABLE leases (
    owner_id TEXT NOT NULL,
    lease_id TEXT NOT NULL CHECK (length(lease_id) = 36 AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    request_id TEXT NOT NULL CHECK (length(request_id) = 36 AND request_id NOT GLOB '*[^0-9a-f-]*'),
    caller_id TEXT NOT NULL CHECK (length(caller_id) = 36 AND caller_id NOT GLOB '*[^0-9a-f-]*'),
    credential_id TEXT NOT NULL CHECK (length(credential_id) = 36 AND credential_id NOT GLOB '*[^0-9a-f-]*'),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    boot_id TEXT NOT NULL CHECK (length(boot_id) = 36 AND boot_id NOT GLOB '*[^0-9a-f-]*'),
    scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 43),
    state TEXT NOT NULL CHECK (state IN ('active','expired','revoked','suspended')),
    activated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > activated_at AND expires_at <= activated_at + 3600000000),
    ended_at INTEGER,
    max_calls INTEGER CHECK (max_calls BETWEEN 1 AND 9007199254740991),
    admitted_calls INTEGER NOT NULL DEFAULT 0 CHECK (admitted_calls >= 0 AND (max_calls IS NULL OR admitted_calls <= max_calls)),
    activation_actor_id TEXT NOT NULL CHECK (length(activation_actor_id) = 36 AND activation_actor_id NOT GLOB '*[^0-9a-f-]*'),
    operation_id TEXT NOT NULL CHECK (length(operation_id) = 36 AND operation_id NOT GLOB '*[^0-9a-f-]*'),
    PRIMARY KEY (owner_id, lease_id),
    UNIQUE (owner_id, request_id),
    UNIQUE (owner_id, activation_actor_id, operation_id),
    UNIQUE (owner_id, lease_id, request_id),
    FOREIGN KEY (owner_id, request_id) REFERENCES requests(owner_id, request_id),
    CHECK ((state = 'active') = (ended_at IS NULL))
) STRICT;
CREATE INDEX leases_owner_live ON leases(owner_id, expires_at, lease_id) WHERE state = 'active';

CREATE TABLE security_events (
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    event_id TEXT NOT NULL CHECK (length(event_id) = 36 AND event_id NOT GLOB '*[^0-9a-f-]*'),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'request.created','request.confirmed','request.denied','request.expired','request.stale',
        'lease.activated','lease.expired','lease.revoked','lease.suspended',
        'vault.created','vault.rewrapped','credential.created','credential.updated','credential.rotated','credential.deleted',
        'policy.changed','activation.rejected','execution.locked','owner_route.rejected',
        'account.created','account.password_changed','access.created','access.revoked','access.renamed','access.ended',
        'connector.created','connector.deleted','connector.visibility_changed','connector.availability_changed')),
    occurred_at INTEGER NOT NULL,
    boot_id TEXT NOT NULL CHECK (length(boot_id) = 36 AND boot_id NOT GLOB '*[^0-9a-f-]*'),
    request_id TEXT CHECK (length(request_id) = 36 AND request_id NOT GLOB '*[^0-9a-f-]*'),
    lease_id TEXT CHECK (length(lease_id) = 36 AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    metadata TEXT NOT NULL CHECK (json_valid(metadata) AND json_type(metadata) = 'object'),
    PRIMARY KEY (owner_id, event_id),
    FOREIGN KEY (owner_id, request_id) REFERENCES requests(owner_id, request_id),
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES leases(owner_id, lease_id, request_id)
) STRICT;
CREATE INDEX security_events_owner_recent ON security_events(owner_id, occurred_at DESC, event_id);

CREATE TABLE invocation_events (
    owner_id TEXT NOT NULL,
    event_id TEXT NOT NULL CHECK (length(event_id) = 36 AND event_id NOT GLOB '*[^0-9a-f-]*'),
    invocation_id TEXT NOT NULL CHECK (length(invocation_id) = 36 AND invocation_id NOT GLOB '*[^0-9a-f-]*'),
    event_type TEXT NOT NULL CHECK (event_type IN ('tool.dispatch.admitted','tool.dispatch.completed')),
    occurred_at INTEGER NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) = 36 AND request_id NOT GLOB '*[^0-9a-f-]*'),
    lease_id TEXT NOT NULL CHECK (length(lease_id) = 36 AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    metadata TEXT NOT NULL CHECK (json_valid(metadata) AND json_type(metadata) = 'object'),
    PRIMARY KEY (owner_id, event_id),
    UNIQUE (owner_id, invocation_id, event_type),
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES leases(owner_id, lease_id, request_id)
) STRICT;
CREATE INDEX invocation_owner_time ON invocation_events(owner_id, occurred_at, event_id);

-- Security and invocation events are append-only.
CREATE TRIGGER security_events_append_only BEFORE UPDATE ON security_events
BEGIN SELECT RAISE(ABORT, 'append-only security event'); END;
CREATE TRIGGER security_events_no_delete BEFORE DELETE ON security_events
BEGIN SELECT RAISE(ABORT, 'append-only security event'); END;
CREATE TRIGGER invocation_events_append_only BEFORE UPDATE ON invocation_events
BEGIN SELECT RAISE(ABORT, 'append-only invocation event'); END;
CREATE TRIGGER invocation_events_no_delete BEFORE DELETE ON invocation_events
BEGIN SELECT RAISE(ABORT, 'append-only invocation event'); END;

CREATE TRIGGER guard_request_binding BEFORE UPDATE ON requests
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.request_id IS NOT OLD.request_id OR NEW.boot_id IS NOT OLD.boot_id
    OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at OR NEW.binding IS NOT OLD.binding
BEGIN SELECT RAISE(ABORT, 'immutable request binding'); END;

CREATE TRIGGER guard_request_terminal BEFORE UPDATE ON requests
WHEN OLD.state NOT IN ('pending','approved') AND (NEW.state IS NOT OLD.state OR NEW.decided_at IS NOT OLD.decided_at
    OR NEW.activation_deadline IS NOT OLD.activation_deadline OR NEW.approver_id IS NOT OLD.approver_id
    OR NEW.authorization_source IS NOT OLD.authorization_source OR NEW.lease_id IS NOT OLD.lease_id)
BEGIN SELECT RAISE(ABORT, 'terminal request'); END;

CREATE TRIGGER guard_request_approval BEFORE UPDATE ON requests
WHEN OLD.state = 'approved' AND (NEW.decided_at IS NOT OLD.decided_at OR NEW.activation_deadline IS NOT OLD.activation_deadline
    OR NEW.approver_id IS NOT OLD.approver_id OR NEW.authorization_source IS NOT OLD.authorization_source)
BEGIN SELECT RAISE(ABORT, 'immutable approval'); END;

CREATE TRIGGER guard_request_transition BEFORE UPDATE ON requests
WHEN NEW.state IS NOT OLD.state AND NOT (
    (OLD.state = 'pending' AND NEW.state IN ('approved','activated','denied','expired','stale')) OR
    (OLD.state = 'approved' AND NEW.state IN ('activated','denied','expired','stale')))
BEGIN SELECT RAISE(ABORT, 'invalid request transition'); END;

CREATE TRIGGER guard_lease_binding BEFORE UPDATE ON leases
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.lease_id IS NOT OLD.lease_id OR NEW.request_id IS NOT OLD.request_id
    OR NEW.caller_id IS NOT OLD.caller_id OR NEW.credential_id IS NOT OLD.credential_id OR NEW.epoch IS NOT OLD.epoch
    OR NEW.boot_id IS NOT OLD.boot_id OR NEW.scope_digest IS NOT OLD.scope_digest OR NEW.activated_at IS NOT OLD.activated_at
    OR NEW.expires_at IS NOT OLD.expires_at OR NEW.max_calls IS NOT OLD.max_calls
    OR NEW.activation_actor_id IS NOT OLD.activation_actor_id OR NEW.operation_id IS NOT OLD.operation_id
BEGIN SELECT RAISE(ABORT, 'immutable lease binding'); END;

CREATE TRIGGER guard_lease_terminal BEFORE UPDATE ON leases
WHEN OLD.state <> 'active' AND (NEW.state IS NOT OLD.state OR NEW.ended_at IS NOT OLD.ended_at OR NEW.admitted_calls IS NOT OLD.admitted_calls)
BEGIN SELECT RAISE(ABORT, 'terminal lease'); END;

CREATE TRIGGER guard_lease_counter BEFORE UPDATE ON leases
WHEN NEW.admitted_calls < OLD.admitted_calls OR NEW.admitted_calls > OLD.admitted_calls + 1
    OR (NEW.state <> 'active' AND NEW.admitted_calls <> OLD.admitted_calls)
BEGIN SELECT RAISE(ABORT, 'invalid admission counter'); END;

-- ---- Vault: ciphertext only ----

CREATE TABLE vault_roots (
    owner_id TEXT PRIMARY KEY REFERENCES owners(owner_id),
    root_id TEXT NOT NULL CHECK (length(root_id) = 36 AND root_id NOT GLOB '*[^0-9a-f-]*'),
    root_version INTEGER NOT NULL CHECK (root_version > 0),
    wrapper_revision INTEGER NOT NULL CHECK (wrapper_revision > 0),
    wrap_count INTEGER NOT NULL DEFAULT 0 CHECK (wrap_count BETWEEN 0 AND 1048576),
    UNIQUE (owner_id, root_id, root_version),
    FOREIGN KEY (owner_id, root_id, root_version, wrapper_revision)
        REFERENCES vault_wrapper_sets(owner_id, root_id, root_version, wrapper_revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE vault_wrapper_sets (
    owner_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    root_version INTEGER NOT NULL,
    wrapper_revision INTEGER NOT NULL CHECK (wrapper_revision > 0),
    passphrase TEXT NOT NULL CHECK (json_valid(passphrase) AND json_type(passphrase) = 'object' AND length(CAST(passphrase AS BLOB)) <= 4096),
    recovery TEXT NOT NULL CHECK (json_valid(recovery) AND json_type(recovery) = 'object' AND length(CAST(recovery AS BLOB)) <= 4096),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_id, root_id, root_version, wrapper_revision),
    FOREIGN KEY (owner_id, root_id, root_version) REFERENCES vault_roots(owner_id, root_id, root_version),
    CHECK ((json_extract(passphrase, '$.owner_id') = owner_id AND json_extract(recovery, '$.owner_id') = owner_id
        AND json_extract(passphrase, '$.root_id') = root_id AND json_extract(recovery, '$.root_id') = root_id
        AND json_type(passphrase, '$.root_version') IN ('integer','text') AND json_extract(passphrase, '$.root_version') = CAST(root_version AS TEXT)
        AND json_type(recovery, '$.root_version') IN ('integer','text') AND json_extract(recovery, '$.root_version') = CAST(root_version AS TEXT)
        AND json_extract(passphrase, '$.method') = 'passphrase' AND json_extract(recovery, '$.method') = 'recovery') IS TRUE)
) STRICT;

CREATE TABLE credential_heads (
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    credential_id TEXT NOT NULL CHECK (length(credential_id) = 36 AND credential_id NOT GLOB '*[^0-9a-f-]*'),
    connector_id TEXT NOT NULL CHECK (length(connector_id) = 36 AND connector_id NOT GLOB '*[^0-9a-f-]*'),
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    revision INTEGER NOT NULL CHECK (revision >= 0), -- zero exists only inside an uncommitted epoch creation
    deleted_at INTEGER,
    PRIMARY KEY (owner_id, credential_id),
    UNIQUE (owner_id, credential_id, connector_id),
    UNIQUE (owner_id, connector_id),
    FOREIGN KEY (owner_id, credential_id, epoch, revision)
        REFERENCES credential_versions(owner_id, credential_id, epoch, revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE credential_epochs (
    owner_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    root_id TEXT NOT NULL,
    root_version INTEGER NOT NULL,
    destination_digest TEXT NOT NULL CHECK (length(destination_digest) = 43),
    destination TEXT NOT NULL CHECK (json_valid(destination) AND json_type(destination) = 'object' AND length(CAST(destination AS BLOB)) <= 16384),
    wrapped_key TEXT NOT NULL CHECK (json_valid(wrapped_key) AND json_type(wrapped_key) = 'object' AND length(CAST(wrapped_key AS BLOB)) <= 4096),
    -- The 12-byte nonce as its canonical unpadded base64url text.
    wrap_nonce TEXT NOT NULL CHECK (length(wrap_nonce) = 16 AND wrap_nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
    write_count INTEGER NOT NULL DEFAULT 0 CHECK (write_count BETWEEN 0 AND 1048576),
    PRIMARY KEY (owner_id, credential_id, epoch),
    UNIQUE (owner_id, root_id, root_version, wrap_nonce),
    FOREIGN KEY (owner_id, credential_id, connector_id) REFERENCES credential_heads(owner_id, credential_id, connector_id),
    FOREIGN KEY (owner_id, root_id, root_version) REFERENCES vault_roots(owner_id, root_id, root_version),
    CHECK ((json_extract(wrapped_key, '$.owner_id') = owner_id AND json_extract(wrapped_key, '$.credential_id') = credential_id
        AND json_extract(wrapped_key, '$.connector_id') = connector_id
        AND json_type(wrapped_key, '$.epoch') IN ('integer','text') AND json_extract(wrapped_key, '$.epoch') = CAST(epoch AS TEXT)
        AND json_extract(wrapped_key, '$.root_id') = root_id
        AND json_type(wrapped_key, '$.root_version') IN ('integer','text') AND json_extract(wrapped_key, '$.root_version') = CAST(root_version AS TEXT)
        AND json_extract(wrapped_key, '$.nonce') = wrap_nonce) IS TRUE)
) STRICT;

CREATE TABLE credential_versions (
    owner_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    nonce TEXT NOT NULL CHECK (length(nonce) = 16 AND nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
    envelope TEXT NOT NULL CHECK (json_valid(envelope) AND json_type(envelope) = 'object' AND length(CAST(envelope AS BLOB)) <= 98304),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_id, credential_id, epoch, revision),
    UNIQUE (owner_id, credential_id, epoch, nonce),
    FOREIGN KEY (owner_id, credential_id, epoch) REFERENCES credential_epochs(owner_id, credential_id, epoch),
    CHECK ((json_extract(envelope, '$.owner_id') = owner_id AND json_extract(envelope, '$.credential_id') = credential_id
        AND json_type(envelope, '$.epoch') IN ('integer','text') AND json_extract(envelope, '$.epoch') = CAST(epoch AS TEXT)
        AND json_type(envelope, '$.revision') IN ('integer','text') AND json_extract(envelope, '$.revision') = CAST(revision AS TEXT)
        AND json_extract(envelope, '$.nonce') = nonce) IS TRUE)
) STRICT;

CREATE TRIGGER guard_vault_root_insert BEFORE INSERT ON vault_roots
WHEN NEW.wrap_count <> 0 OR NEW.wrapper_revision <> 1 OR NEW.root_version <> 1
BEGIN SELECT RAISE(ABORT, 'invalid initial vault root'); END;

CREATE TRIGGER guard_vault_root_update BEFORE UPDATE ON vault_roots
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.root_id IS NOT OLD.root_id OR NEW.root_version IS NOT OLD.root_version
    OR NOT ((NEW.wrapper_revision = OLD.wrapper_revision + 1 AND NEW.wrap_count = OLD.wrap_count)
         OR (NEW.wrapper_revision = OLD.wrapper_revision AND NEW.wrap_count = OLD.wrap_count + 1))
BEGIN SELECT RAISE(ABORT, 'invalid vault root update'); END;

CREATE TRIGGER vault_wrapper_sets_append_only BEFORE UPDATE ON vault_wrapper_sets
BEGIN SELECT RAISE(ABORT, 'append-only wrapper set'); END;

CREATE TRIGGER guard_credential_head_identity BEFORE UPDATE ON credential_heads
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.credential_id IS NOT OLD.credential_id OR NEW.connector_id IS NOT OLD.connector_id
    OR OLD.deleted_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'immutable credential identity or tombstone'); END;

CREATE TRIGGER guard_credential_head_delete BEFORE UPDATE ON credential_heads
WHEN NEW.deleted_at IS NOT NULL AND (NEW.epoch IS NOT OLD.epoch OR NEW.revision IS NOT OLD.revision)
BEGIN SELECT RAISE(ABORT, 'invalid credential deletion'); END;

CREATE TRIGGER guard_credential_head_version BEFORE UPDATE ON credential_heads
WHEN NEW.deleted_at IS NULL AND NOT ((NEW.epoch = OLD.epoch AND NEW.revision = OLD.revision + 1)
    OR (NEW.epoch = OLD.epoch + 1 AND NEW.revision = 0))
BEGIN SELECT RAISE(ABORT, 'invalid credential version update'); END;

CREATE TRIGGER guard_credential_epoch_insert BEFORE INSERT ON credential_epochs
BEGIN
    SELECT RAISE(ABORT, 'invalid initial write count') WHERE NEW.write_count IS NOT 0;
    SELECT RAISE(ABORT, 'vault wrapping key write cap') WHERE NOT EXISTS (SELECT 1 FROM vault_roots
        WHERE owner_id = NEW.owner_id AND root_id = NEW.root_id AND root_version = NEW.root_version AND wrap_count < 1048576);
    UPDATE vault_roots SET wrap_count = wrap_count + 1
        WHERE owner_id = NEW.owner_id AND root_id = NEW.root_id AND root_version = NEW.root_version;
END;

CREATE TRIGGER guard_credential_epoch_update BEFORE UPDATE ON credential_epochs
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.credential_id IS NOT OLD.credential_id OR NEW.connector_id IS NOT OLD.connector_id
    OR NEW.epoch IS NOT OLD.epoch OR NEW.root_id IS NOT OLD.root_id OR NEW.root_version IS NOT OLD.root_version
    OR NEW.destination_digest IS NOT OLD.destination_digest OR NEW.destination IS NOT OLD.destination
    OR NEW.wrapped_key IS NOT OLD.wrapped_key OR NEW.wrap_nonce IS NOT OLD.wrap_nonce
    OR NEW.write_count IS NOT OLD.write_count + 1
BEGIN SELECT RAISE(ABORT, 'immutable credential epoch or invalid write count'); END;

CREATE TRIGGER credential_versions_append_only BEFORE UPDATE ON credential_versions
BEGIN SELECT RAISE(ABORT, 'append-only credential version'); END;

CREATE TRIGGER admit_credential_version BEFORE INSERT ON credential_versions
BEGIN
    SELECT RAISE(ABORT, 'stale credential version') WHERE NOT EXISTS (SELECT 1 FROM credential_heads
        WHERE owner_id = NEW.owner_id AND credential_id = NEW.credential_id AND deleted_at IS NULL
        AND epoch = NEW.epoch AND revision + 1 = NEW.revision);
    SELECT RAISE(ABORT, 'invalid credential context') WHERE NOT EXISTS (SELECT 1 FROM credential_heads h
        JOIN credential_epochs e ON e.owner_id = h.owner_id AND e.credential_id = h.credential_id AND e.epoch = NEW.epoch
        WHERE h.owner_id = NEW.owner_id AND h.credential_id = NEW.credential_id
        AND json_extract(NEW.envelope, '$.connector_id') = h.connector_id
        AND json_extract(NEW.envelope, '$.destination_profile_sha256') = e.destination_digest);
    SELECT RAISE(ABORT, 'credential epoch write cap') WHERE NOT EXISTS (SELECT 1 FROM credential_epochs
        WHERE owner_id = NEW.owner_id AND credential_id = NEW.credential_id AND epoch = NEW.epoch AND write_count < 1048576);
    UPDATE credential_epochs SET write_count = write_count + 1
        WHERE owner_id = NEW.owner_id AND credential_id = NEW.credential_id AND epoch = NEW.epoch;
    UPDATE credential_heads SET revision = NEW.revision
        WHERE owner_id = NEW.owner_id AND credential_id = NEW.credential_id;
END;

-- ---- Owner approval policy ----

CREATE TABLE approval_policies (
    owner_id TEXT PRIMARY KEY REFERENCES owners(owner_id),
    mode TEXT NOT NULL CHECK (mode IN ('none','confirm')),
    revision INTEGER NOT NULL CHECK (revision > 1), -- revision 1 is the implicit default
    changed_at INTEGER NOT NULL,
    changed_by TEXT NOT NULL CHECK (length(changed_by) = 36 AND changed_by NOT GLOB '*[^0-9a-f-]*')
) STRICT;

CREATE TRIGGER guard_approval_policy_insert BEFORE INSERT ON approval_policies
WHEN NEW.revision <> 2
BEGIN SELECT RAISE(ABORT, 'invalid initial approval policy'); END;

CREATE TRIGGER guard_approval_policy_update BEFORE UPDATE ON approval_policies
WHEN NEW.owner_id IS NOT OLD.owner_id OR NEW.revision <> OLD.revision + 1 OR NEW.changed_at < OLD.changed_at
BEGIN SELECT RAISE(ABORT, 'invalid approval policy update'); END;

-- ---- Catalog: sealed records; plain columns exist for constraints and indexes ----

CREATE TABLE catalog_accounts (
    owner_id TEXT PRIMARY KEY REFERENCES owners(owner_id),
    username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 200),
    created_at INTEGER,
    updated_at INTEGER,
    sealed BLOB NOT NULL
) STRICT;

CREATE TABLE catalog_access (
    access_id TEXT PRIMARY KEY CHECK (length(access_id) BETWEEN 1 AND 200),
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    public_id TEXT UNIQUE,
    -- HMAC of the stored token verifier under a key derived from the catalog key.
    secret_digest BLOB NOT NULL UNIQUE CHECK (length(secret_digest) = 32),
    kind TEXT NOT NULL CHECK (kind IN ('api_key','browser','oauth','mcp')),
    role TEXT NOT NULL CHECK (role IN ('admin','client')),
    created_at INTEGER,
    updated_at INTEGER,
    last_used_at INTEGER,
    expires_at INTEGER,
    ended_at INTEGER,
    revoked_at INTEGER,
    deleted_at INTEGER,
    sealed BLOB NOT NULL
) STRICT;
CREATE INDEX catalog_access_owner ON catalog_access(owner_id, kind);

-- A deleted connector keeps its row as a credential-free tombstone whose sealed
-- payload is only its lifecycle.
CREATE TABLE catalog_connectors (
    connector_id TEXT PRIMARY KEY CHECK (length(connector_id) = 36 AND connector_id NOT GLOB '*[^0-9a-f-]*'),
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    name TEXT CHECK (length(name) BETWEEN 1 AND 20 AND name NOT GLOB '*[^a-z0-9-]*'),
    auth_type TEXT NOT NULL CHECK (auth_type IN ('','none','headers','bearer','api_key')),
    created_at INTEGER,
    updated_at INTEGER,
    deleted_at INTEGER,
    sealed BLOB NOT NULL,
    CHECK ((deleted_at IS NULL) = (name IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX catalog_connectors_owner_name ON catalog_connectors(owner_id, name) WHERE deleted_at IS NULL;

-- Discovery and visibility are keyed by provider name: configured upstreams
-- have them too.
CREATE TABLE catalog_discovery (
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    updated_at INTEGER,
    sealed BLOB NOT NULL,
    PRIMARY KEY (owner_id, provider)
) STRICT;

CREATE TABLE catalog_visibility (
    owner_id TEXT NOT NULL REFERENCES owners(owner_id),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    mode TEXT NOT NULL CHECK (mode IN ('all','selected')),
    disabled INTEGER NOT NULL CHECK (disabled IN (0, 1)),
    created_at INTEGER,
    updated_at INTEGER,
    sealed BLOB NOT NULL,
    PRIMARY KEY (owner_id, provider)
) STRICT;

-- ---- Tool-call history ----

-- Append-only. `record` holds the writer's exact JSON encoding; the other
-- columns are derived from it. Rows are never deleted with connectors or
-- accounts.
CREATE TABLE history_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 200),
    schema_version INTEGER NOT NULL CHECK (schema_version BETWEEN 0 AND 2),
    event_type TEXT CHECK (event_type IN ('tool.dispatch.admitted','tool.dispatch.completed','tool.dispatch.denied')),
    invocation_id TEXT,
    tool_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    upstream TEXT NOT NULL,
    status TEXT NOT NULL,
    actor_access_id TEXT NOT NULL,
    -- Unix nanoseconds.
    ts_ns INTEGER NOT NULL,
    history_ns INTEGER NOT NULL,
    -- Timing for performance summaries; buckets use the reader's log2 scale.
    timed INTEGER NOT NULL CHECK (timed IN (0, 1)),
    failed INTEGER NOT NULL CHECK (failed IN (0, 1)),
    forwarded INTEGER NOT NULL CHECK (forwarded IN (0, 1)),
    handler_us INTEGER NOT NULL,
    gateway_us INTEGER NOT NULL,
    upstream_us INTEGER NOT NULL,
    handler_bucket INTEGER NOT NULL CHECK (handler_bucket BETWEEN 0 AND 31),
    gateway_bucket INTEGER NOT NULL CHECK (gateway_bucket BETWEEN 0 AND 31),
    upstream_bucket INTEGER NOT NULL CHECK (upstream_bucket BETWEEN 0 AND 31),
    record TEXT NOT NULL,
    CHECK ((schema_version = 2) = (event_type IS NOT NULL AND invocation_id IS NOT NULL)),
    UNIQUE (owner_id, event_id),
    UNIQUE (owner_id, invocation_id, event_type)
) STRICT;
CREATE TRIGGER history_events_append_only BEFORE UPDATE ON history_events
BEGIN SELECT RAISE(ABORT, 'append-only history'); END;
CREATE TRIGGER history_events_no_delete BEFORE DELETE ON history_events
BEGIN SELECT RAISE(ABORT, 'append-only history'); END;

-- Pages read settled events (everything but admissions) from one index per
-- filter, in history order, and open admissions from history_open. The index
-- predicate matches the query's `settled` expression exactly.
CREATE INDEX history_owner_recent ON history_events(owner_id, history_ns DESC, event_id DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_tool ON history_events(owner_id, tool_id, history_ns DESC, event_id DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_upstream ON history_events(owner_id, upstream, history_ns DESC, event_id DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_status ON history_events(owner_id, status, history_ns DESC, event_id DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_actor ON history_events(owner_id, actor_access_id, history_ns DESC, event_id DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_invocation ON history_events(owner_id, invocation_id) WHERE invocation_id IS NOT NULL;

-- The latest name snapshot of each tool, for the tool filter. Each insert
-- moves it forward only.
CREATE TABLE history_tools (
    owner_id TEXT NOT NULL,
    tool_id TEXT NOT NULL CHECK (tool_id <> ''),
    tool TEXT NOT NULL,
    upstream TEXT NOT NULL,
    last_ns INTEGER NOT NULL,
    last_event_id TEXT NOT NULL,
    PRIMARY KEY (owner_id, tool_id)
) STRICT;

-- Admissions whose completion is not stored: exactly the calls the history
-- shows with an unknown outcome.
CREATE TABLE history_open (
    owner_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    history_ns INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (owner_id, invocation_id)
) STRICT;
CREATE INDEX history_open_recent ON history_open(owner_id, history_ns DESC, event_id DESC);
