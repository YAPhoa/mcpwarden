-- Owner approval policy and owner-route audit types. Still no key material.
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

ALTER TABLE mcpwarden_security.security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE mcpwarden_security.security_events ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
    'request.created','request.confirmed','request.denied','request.expired','request.stale',
    'lease.activated','lease.expired','lease.revoked','lease.suspended',
    'vault.created','vault.rewrapped','credential.created','credential.updated','credential.rotated','credential.deleted',
    'policy.changed','activation.rejected','execution.locked','owner_route.rejected'));
CREATE INDEX security_events_owner_recent ON mcpwarden_security.security_events(owner_id, occurred_at DESC, event_id);

REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcpwarden_security FROM PUBLIC;
