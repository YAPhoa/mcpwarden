-- Security metadata only. No CEKs, vault roots, credentials, or tool payloads.
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
    binding jsonb NOT NULL CHECK (jsonb_typeof(binding) = 'object'
        AND binding->>'id' = request_id::text
        AND binding->>'boot_id' = boot_id::text
        AND binding#>>'{scope,owner_id}' = owner_id),
    state text NOT NULL CHECK (state IN ('pending','approved','activated','denied','expired','stale')),
    decided_at timestamptz,
    activation_deadline timestamptz,
    approver_id uuid,
    authorization_source text CHECK (authorization_source IN ('client_activation','owner_confirmation')),
    lease_id uuid,
    PRIMARY KEY (owner_id, request_id),
    CHECK (state <> 'pending' OR (decided_at IS NULL AND activation_deadline IS NULL AND approver_id IS NULL AND authorization_source IS NULL AND lease_id IS NULL)),
    CHECK (state NOT IN ('approved','activated') OR (decided_at IS NOT NULL AND activation_deadline IS NOT NULL AND approver_id IS NOT NULL AND authorization_source IS NOT NULL)),
    CHECK (state <> 'approved' OR (binding->>'mode' = 'confirm' AND authorization_source = 'owner_confirmation' AND lease_id IS NULL)),
    CHECK (state <> 'activated' OR lease_id IS NOT NULL),
    CHECK (activation_deadline IS NULL OR activation_deadline <= expires_at)
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
    event_type text NOT NULL CHECK (event_type IN ('request.created','request.confirmed','request.denied','request.expired','request.stale','lease.activated','lease.expired','lease.revoked','lease.suspended')),
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

REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcpwarden_security FROM PUBLIC;
