-- mcpwarden schema, version 1. Databases created by development builds
-- before this baseline are refused; create a new database.

-- ---- Leases and security events ----

CREATE SCHEMA IF NOT EXISTS mcpwarden_security;
REVOKE ALL ON SCHEMA mcpwarden_security FROM PUBLIC;

CREATE TABLE mcpwarden_security.schema_migrations (
    version integer PRIMARY KEY,
    sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE mcpwarden_security.owners (
    owner_id text PRIMARY KEY CHECK (length(owner_id) BETWEEN 1 AND 512)
);

CREATE TABLE mcpwarden_security.requests (
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    request_id uuid NOT NULL,
    boot_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    binding jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','approved','activated','denied','expired','stale')),
    decided_at timestamptz,
    activation_deadline timestamptz,
    approver_id uuid,
    authorization_source text CHECK (authorization_source IN ('client_activation','owner_confirmation')),
    lease_id uuid,
    PRIMARY KEY (owner_id, request_id),
    CHECK (state <> 'pending' OR (decided_at IS NULL AND activation_deadline IS NULL AND approver_id IS NULL AND authorization_source IS NULL AND lease_id IS NULL)),
    CHECK (state NOT IN ('approved','activated') OR (decided_at IS NOT NULL AND activation_deadline IS NOT NULL AND approver_id IS NOT NULL AND authorization_source IS NOT NULL)),
    CHECK (state <> 'activated' OR lease_id IS NOT NULL),
    CHECK (activation_deadline IS NULL OR activation_deadline <= expires_at),
    -- A CHECK that evaluates to NULL passes, so checks that compare JSON
    -- fields which may be missing are wrapped in IS TRUE.
    CONSTRAINT requests_binding_identity CHECK ((jsonb_typeof(binding) = 'object'
        AND binding->>'id' = request_id::text
        AND binding->>'boot_id' = boot_id::text
        AND binding#>>'{scope,owner_id}' = owner_id) IS TRUE),
    CONSTRAINT requests_approved_mode CHECK ((state <> 'approved'
        OR (binding->>'mode' = 'confirm' AND authorization_source = 'owner_confirmation' AND lease_id IS NULL)) IS TRUE)
);
CREATE INDEX requests_owner_recent ON mcpwarden_security.requests(owner_id, created_at);
CREATE INDEX requests_owner_live ON mcpwarden_security.requests(owner_id) WHERE state IN ('pending','approved');

CREATE TABLE mcpwarden_security.leases (
    owner_id text NOT NULL,
    lease_id uuid NOT NULL,
    request_id uuid NOT NULL,
    caller_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    boot_id uuid NOT NULL,
    scope_digest text NOT NULL CHECK (length(scope_digest) = 43),
    state text NOT NULL CHECK (state IN ('active','expired','revoked','suspended')),
    activated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > activated_at AND expires_at <= activated_at + interval '1 hour'),
    ended_at timestamptz,
    max_calls bigint CHECK (max_calls BETWEEN 1 AND 9007199254740991),
    admitted_calls bigint NOT NULL DEFAULT 0 CHECK (admitted_calls >= 0 AND (max_calls IS NULL OR admitted_calls <= max_calls)),
    activation_actor_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    PRIMARY KEY (owner_id, lease_id),
    UNIQUE (owner_id, request_id),
    UNIQUE (owner_id, activation_actor_id, operation_id),
    UNIQUE (owner_id, lease_id, request_id),
    FOREIGN KEY (owner_id, request_id) REFERENCES mcpwarden_security.requests(owner_id, request_id),
    CHECK ((state = 'active') = (ended_at IS NULL))
);
CREATE INDEX leases_owner_live ON mcpwarden_security.leases(owner_id, expires_at, lease_id) WHERE state = 'active';
ALTER TABLE mcpwarden_security.requests ADD CONSTRAINT requests_lease_binding
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES mcpwarden_security.leases(owner_id, lease_id, request_id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mcpwarden_security.security_events (
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    event_id uuid NOT NULL,
    event_type text NOT NULL CONSTRAINT security_events_event_type_check CHECK (event_type IN (
        'request.created','request.confirmed','request.denied','request.expired','request.stale',
        'lease.activated','lease.expired','lease.revoked','lease.suspended',
        'vault.created','vault.rewrapped','credential.created','credential.updated','credential.rotated','credential.deleted',
        'policy.changed','activation.rejected','execution.locked','owner_route.rejected',
        'account.created','account.password_changed','access.created','access.revoked','access.renamed','access.ended',
        'connector.created','connector.deleted','connector.visibility_changed','connector.availability_changed')),
    occurred_at timestamptz NOT NULL,
    boot_id uuid NOT NULL,
    request_id uuid,
    lease_id uuid,
    metadata jsonb NOT NULL CHECK (jsonb_typeof(metadata) = 'object'),
    PRIMARY KEY (owner_id, event_id),
    FOREIGN KEY (owner_id, request_id) REFERENCES mcpwarden_security.requests(owner_id, request_id),
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES mcpwarden_security.leases(owner_id, lease_id, request_id)
);

CREATE TABLE mcpwarden_security.invocation_events (
    owner_id text NOT NULL,
    event_id uuid NOT NULL,
    invocation_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('tool.dispatch.admitted','tool.dispatch.completed')),
    occurred_at timestamptz NOT NULL,
    request_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    metadata jsonb NOT NULL CHECK (jsonb_typeof(metadata) = 'object'),
    PRIMARY KEY (owner_id, event_id),
    UNIQUE (owner_id, invocation_id, event_type),
    FOREIGN KEY (owner_id, lease_id, request_id) REFERENCES mcpwarden_security.leases(owner_id, lease_id, request_id)
);
CREATE INDEX invocation_owner_time ON mcpwarden_security.invocation_events(owner_id, occurred_at, event_id);

CREATE FUNCTION mcpwarden_security.guard_request_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.owner_id,NEW.request_id,NEW.boot_id,NEW.created_at,NEW.expires_at,NEW.binding)
        IS DISTINCT FROM ROW(OLD.owner_id,OLD.request_id,OLD.boot_id,OLD.created_at,OLD.expires_at,OLD.binding) THEN
        RAISE EXCEPTION 'immutable request binding' USING ERRCODE = '23514';
    END IF;
    IF OLD.state NOT IN ('pending','approved') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal request' USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'approved' AND ROW(NEW.decided_at,NEW.activation_deadline,NEW.approver_id,NEW.authorization_source)
        IS DISTINCT FROM ROW(OLD.decided_at,OLD.activation_deadline,OLD.approver_id,OLD.authorization_source) THEN
        RAISE EXCEPTION 'immutable approval' USING ERRCODE = '23514';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT
        ((OLD.state = 'pending' AND NEW.state IN ('approved','activated','denied','expired','stale')) OR
         (OLD.state = 'approved' AND NEW.state IN ('activated','denied','expired','stale'))) THEN
        RAISE EXCEPTION 'invalid request transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_request_update BEFORE UPDATE ON mcpwarden_security.requests
    FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_request_update();

CREATE FUNCTION mcpwarden_security.guard_lease_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.owner_id,NEW.lease_id,NEW.request_id,NEW.caller_id,NEW.credential_id,NEW.epoch,NEW.boot_id,NEW.scope_digest,
           NEW.activated_at,NEW.expires_at,NEW.max_calls,NEW.activation_actor_id,NEW.operation_id)
        IS DISTINCT FROM ROW(OLD.owner_id,OLD.lease_id,OLD.request_id,OLD.caller_id,OLD.credential_id,OLD.epoch,OLD.boot_id,OLD.scope_digest,
           OLD.activated_at,OLD.expires_at,OLD.max_calls,OLD.activation_actor_id,OLD.operation_id) THEN
        RAISE EXCEPTION 'immutable lease binding' USING ERRCODE = '23514';
    END IF;
    IF OLD.state <> 'active' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal lease' USING ERRCODE = '23514';
    END IF;
    IF NEW.admitted_calls < OLD.admitted_calls OR NEW.admitted_calls > OLD.admitted_calls + 1 OR
        (NEW.state <> 'active' AND NEW.admitted_calls <> OLD.admitted_calls) THEN
        RAISE EXCEPTION 'invalid admission counter' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_lease_update BEFORE UPDATE ON mcpwarden_security.leases
    FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_lease_update();

-- ---- Owner vault (ciphertext only) ----

CREATE TABLE mcpwarden_security.vault_roots (
    owner_id text PRIMARY KEY REFERENCES mcpwarden_security.owners(owner_id),
    root_id uuid NOT NULL,
    root_version bigint NOT NULL CHECK (root_version > 0),
    wrapper_revision bigint NOT NULL CHECK (wrapper_revision > 0),
    wrap_count bigint NOT NULL DEFAULT 0 CHECK (wrap_count BETWEEN 0 AND 1048576),
    UNIQUE (owner_id,root_id,root_version)
);
CREATE TABLE mcpwarden_security.vault_wrapper_sets (
    owner_id text NOT NULL,
    root_id uuid NOT NULL,
    root_version bigint NOT NULL,
    wrapper_revision bigint NOT NULL CHECK (wrapper_revision > 0),
    passphrase jsonb NOT NULL CHECK (jsonb_typeof(passphrase)='object' AND octet_length(passphrase::text)<=4096),
    recovery jsonb NOT NULL CHECK (jsonb_typeof(recovery)='object' AND octet_length(recovery::text)<=4096),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id,root_id,root_version,wrapper_revision),
    FOREIGN KEY (owner_id,root_id,root_version) REFERENCES mcpwarden_security.vault_roots(owner_id,root_id,root_version),
    CHECK ((passphrase->>'owner_id'=owner_id AND recovery->>'owner_id'=owner_id
       AND passphrase->>'root_id'=root_id::text AND recovery->>'root_id'=root_id::text
       AND passphrase->>'root_version'=root_version::text AND recovery->>'root_version'=root_version::text
       AND passphrase->>'method'='passphrase' AND recovery->>'method'='recovery') IS TRUE)
);
ALTER TABLE mcpwarden_security.vault_roots ADD CONSTRAINT current_wrapper_set
    FOREIGN KEY (owner_id,root_id,root_version,wrapper_revision)
    REFERENCES mcpwarden_security.vault_wrapper_sets(owner_id,root_id,root_version,wrapper_revision) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mcpwarden_security.credential_heads (
    owner_id text NOT NULL REFERENCES mcpwarden_security.owners(owner_id),
    credential_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    revision bigint NOT NULL CHECK (revision >= 0), -- zero exists only inside an uncommitted epoch creation
    deleted_at timestamptz,
    PRIMARY KEY (owner_id,credential_id),
    UNIQUE (owner_id,credential_id,connector_id),
    UNIQUE (owner_id,connector_id)
);
CREATE TABLE mcpwarden_security.credential_epochs (
    owner_id text NOT NULL,
    credential_id uuid NOT NULL,
    connector_id uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    root_id uuid NOT NULL,
    root_version bigint NOT NULL,
    destination_digest text NOT NULL CHECK (length(destination_digest)=43),
    destination jsonb NOT NULL CHECK (jsonb_typeof(destination)='object' AND octet_length(destination::text)<=16384),
    wrapped_key jsonb NOT NULL CHECK (jsonb_typeof(wrapped_key)='object' AND octet_length(wrapped_key::text)<=4096),
    wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce)=12),
    write_count bigint NOT NULL DEFAULT 0 CHECK (write_count BETWEEN 0 AND 1048576),
    PRIMARY KEY (owner_id,credential_id,epoch),
    UNIQUE (owner_id,root_id,root_version,wrap_nonce),
    FOREIGN KEY (owner_id,credential_id,connector_id) REFERENCES mcpwarden_security.credential_heads(owner_id,credential_id,connector_id),
    FOREIGN KEY (owner_id,root_id,root_version) REFERENCES mcpwarden_security.vault_roots(owner_id,root_id,root_version),
    CHECK ((wrapped_key->>'owner_id'=owner_id AND wrapped_key->>'credential_id'=credential_id::text
        AND wrapped_key->>'connector_id'=connector_id::text AND wrapped_key->>'epoch'=epoch::text
        AND wrapped_key->>'root_id'=root_id::text AND wrapped_key->>'root_version'=root_version::text
        AND wrapped_key->>'nonce'=rtrim(translate(encode(wrap_nonce,'base64'),'+/','-_'),'=')) IS TRUE)
);
CREATE TABLE mcpwarden_security.credential_versions (
    owner_id text NOT NULL,
    credential_id uuid NOT NULL,
    epoch bigint NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    nonce bytea NOT NULL CHECK (octet_length(nonce)=12),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope)='object' AND octet_length(envelope::text)<=98304),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id,credential_id,epoch,revision),
    UNIQUE (owner_id,credential_id,epoch,nonce),
    FOREIGN KEY (owner_id,credential_id,epoch) REFERENCES mcpwarden_security.credential_epochs(owner_id,credential_id,epoch),
    CHECK ((envelope->>'owner_id'=owner_id AND envelope->>'credential_id'=credential_id::text
        AND envelope->>'epoch'=epoch::text AND envelope->>'revision'=revision::text
        AND envelope->>'nonce'=rtrim(translate(encode(nonce,'base64'),'+/','-_'),'=')) IS TRUE)
);
ALTER TABLE mcpwarden_security.credential_heads ADD CONSTRAINT current_credential_version
    FOREIGN KEY (owner_id,credential_id,epoch,revision)
    REFERENCES mcpwarden_security.credential_versions(owner_id,credential_id,epoch,revision) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION mcpwarden_security.guard_vault_root() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.wrap_count<>0 OR NEW.wrapper_revision<>1 OR NEW.root_version<>1 THEN
            RAISE EXCEPTION 'invalid initial vault root' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.owner_id,NEW.root_id,NEW.root_version) IS DISTINCT FROM ROW(OLD.owner_id,OLD.root_id,OLD.root_version)
       OR NOT ((NEW.wrapper_revision=OLD.wrapper_revision+1 AND NEW.wrap_count=OLD.wrap_count)
            OR (NEW.wrapper_revision=OLD.wrapper_revision AND NEW.wrap_count=OLD.wrap_count+1)) THEN
        RAISE EXCEPTION 'invalid vault root update' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_vault_root BEFORE INSERT OR UPDATE ON mcpwarden_security.vault_roots FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_vault_root();

CREATE FUNCTION mcpwarden_security.guard_credential_head() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.owner_id,NEW.credential_id,NEW.connector_id) IS DISTINCT FROM ROW(OLD.owner_id,OLD.credential_id,OLD.connector_id)
       OR OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'immutable credential identity or tombstone' USING ERRCODE='23514';
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        IF ROW(NEW.epoch,NEW.revision) IS DISTINCT FROM ROW(OLD.epoch,OLD.revision) THEN
            RAISE EXCEPTION 'invalid credential deletion' USING ERRCODE='23514';
        END IF;
    ELSIF NOT ((NEW.epoch=OLD.epoch AND NEW.revision=OLD.revision+1) OR (NEW.epoch=OLD.epoch+1 AND NEW.revision=0)) THEN
        RAISE EXCEPTION 'invalid credential version update' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_credential_head BEFORE UPDATE ON mcpwarden_security.credential_heads FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_credential_head();

CREATE FUNCTION mcpwarden_security.guard_credential_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.write_count<>0 THEN RAISE EXCEPTION 'invalid initial write count' USING ERRCODE='23514'; END IF;
        UPDATE mcpwarden_security.vault_roots SET wrap_count=wrap_count+1
            WHERE owner_id=NEW.owner_id AND root_id=NEW.root_id AND root_version=NEW.root_version AND wrap_count<1048576;
        IF NOT FOUND THEN RAISE EXCEPTION 'vault wrapping key write cap' USING ERRCODE='23514'; END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW)-'write_count') IS DISTINCT FROM (to_jsonb(OLD)-'write_count') OR NEW.write_count<>OLD.write_count+1 THEN
        RAISE EXCEPTION 'immutable credential epoch or invalid write count' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_credential_epoch BEFORE INSERT OR UPDATE ON mcpwarden_security.credential_epochs FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_credential_epoch();

CREATE FUNCTION mcpwarden_security.admit_credential_version() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE head mcpwarden_security.credential_heads;
DECLARE expected_digest text;
BEGIN
    SELECT * INTO head FROM mcpwarden_security.credential_heads WHERE owner_id=NEW.owner_id AND credential_id=NEW.credential_id FOR UPDATE;
    IF NOT FOUND OR head.deleted_at IS NOT NULL OR head.epoch<>NEW.epoch OR head.revision+1<>NEW.revision THEN
        RAISE EXCEPTION 'stale credential version' USING ERRCODE='23514';
    END IF;
    SELECT destination_digest INTO expected_digest FROM mcpwarden_security.credential_epochs
        WHERE owner_id=NEW.owner_id AND credential_id=NEW.credential_id AND epoch=NEW.epoch;
    IF (NEW.envelope->>'connector_id') IS DISTINCT FROM head.connector_id::text
       OR expected_digest IS NULL OR (NEW.envelope->>'destination_profile_sha256') IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'invalid credential context' USING ERRCODE='23514';
    END IF;
    UPDATE mcpwarden_security.credential_epochs SET write_count=write_count+1
        WHERE owner_id=NEW.owner_id AND credential_id=NEW.credential_id AND epoch=NEW.epoch AND write_count<1048576;
    IF NOT FOUND THEN RAISE EXCEPTION 'credential epoch write cap' USING ERRCODE='23514'; END IF;
    UPDATE mcpwarden_security.credential_heads SET revision=NEW.revision
        WHERE owner_id=NEW.owner_id AND credential_id=NEW.credential_id;
    RETURN NEW;
END $$;
CREATE TRIGGER admit_credential_version BEFORE INSERT ON mcpwarden_security.credential_versions FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.admit_credential_version();

-- ---- Owner approval policy ----

CREATE TABLE mcpwarden_security.approval_policies (
    owner_id text PRIMARY KEY REFERENCES mcpwarden_security.owners(owner_id),
    mode text NOT NULL CHECK (mode IN ('none','confirm')),
    revision bigint NOT NULL CHECK (revision > 1), -- revision 1 is the implicit default
    changed_at timestamptz NOT NULL,
    changed_by uuid NOT NULL
);

CREATE FUNCTION mcpwarden_security.guard_approval_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>2 THEN
            RAISE EXCEPTION 'invalid initial approval policy' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.revision<>OLD.revision+1 OR NEW.changed_at<OLD.changed_at THEN
        RAISE EXCEPTION 'invalid approval policy update' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_approval_policy BEFORE INSERT OR UPDATE ON mcpwarden_security.approval_policies
    FOR EACH ROW EXECUTE FUNCTION mcpwarden_security.guard_approval_policy();

CREATE INDEX security_events_owner_recent ON mcpwarden_security.security_events(owner_id, occurred_at DESC, event_id);

-- ---- Gateway catalog ----

-- Every secret-bearing value (password salts and hashes, access-token
-- verifiers, cached tool schemas) is inside `sealed`: AES-GCM ciphertext made
-- by the gateway with its catalog key before the value reaches PostgreSQL. The
-- plain columns exist for constraints, indexes and locking. Connector
-- credentials are never here; they live in the owner vault.

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
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz,
    sealed bytea NOT NULL,
    CHECK ((deleted_at IS NULL) = (name IS NOT NULL))
);
CREATE UNIQUE INDEX catalog_connectors_owner_name ON mcpwarden_security.catalog_connectors(owner_id, name) WHERE deleted_at IS NULL;

-- Discovery and visibility are keyed by provider name: configured (static)
-- upstreams have them too.
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

-- ---- Tool-call history ----

-- Append-only. `record` holds the writer's exact JSON encoding; the other
-- columns are derived from it. Rows are never deleted with connectors or
-- accounts.
CREATE TABLE mcpwarden_security.history_events (
    seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id text NOT NULL,
    event_id text NOT NULL CHECK (length(event_id) BETWEEN 1 AND 200),
    schema_version smallint NOT NULL CHECK (schema_version = 2),
    event_type text NOT NULL CHECK (event_type IN ('tool.dispatch.admitted','tool.dispatch.completed','tool.dispatch.denied')),
    invocation_id text NOT NULL CHECK (length(invocation_id) BETWEEN 1 AND 200),
    tool_id text NOT NULL,
    tool text NOT NULL,
    upstream text NOT NULL,
    status text NOT NULL,
    actor_access_id text NOT NULL,
    -- Unix nanoseconds.
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
    UNIQUE (owner_id, event_id),
    UNIQUE (owner_id, invocation_id, event_type)
);
-- Pages read settled events (everything but admissions) from one index per
-- filter, in history order, and open admissions from history_open. Time
-- ranges filter on history_ns, the order the list already uses. The index
-- predicate matches the query's `settled` expression exactly.
CREATE INDEX history_owner_recent ON mcpwarden_security.history_events(owner_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE event_type <> 'tool.dispatch.admitted';
CREATE INDEX history_owner_tool ON mcpwarden_security.history_events(owner_id, tool_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE event_type <> 'tool.dispatch.admitted';
CREATE INDEX history_owner_upstream ON mcpwarden_security.history_events(owner_id, upstream, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE event_type <> 'tool.dispatch.admitted';
CREATE INDEX history_owner_status ON mcpwarden_security.history_events(owner_id, status, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE event_type <> 'tool.dispatch.admitted';
CREATE INDEX history_owner_actor ON mcpwarden_security.history_events(owner_id, actor_access_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE event_type <> 'tool.dispatch.admitted';

-- The latest name snapshot of each tool, for the tool filter. Each history
-- insert moves it forward only, so an out-of-order write never replaces a
-- newer name.
CREATE TABLE mcpwarden_security.history_tools (
    owner_id text NOT NULL,
    tool_id text NOT NULL CHECK (tool_id <> ''),
    tool text NOT NULL,
    upstream text NOT NULL,
    last_ns bigint NOT NULL,
    last_event_id text COLLATE "C" NOT NULL,
    PRIMARY KEY (owner_id, tool_id)
);

-- Admissions whose completion is not stored: exactly the calls the history
-- shows with an unknown outcome.
CREATE TABLE mcpwarden_security.history_open (
    owner_id text NOT NULL,
    invocation_id text NOT NULL,
    history_ns bigint NOT NULL,
    event_id text NOT NULL,
    PRIMARY KEY (owner_id, invocation_id)
);
CREATE INDEX history_open_recent ON mcpwarden_security.history_open(owner_id, history_ns DESC, event_id COLLATE "C" DESC);

REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcpwarden_security FROM PUBLIC;
