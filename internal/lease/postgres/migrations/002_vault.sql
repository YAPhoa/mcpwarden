-- Ciphertext only. This migration cannot unlock a vault or convert legacy data.
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

REVOKE ALL ON ALL TABLES IN SCHEMA mcpwarden_security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcpwarden_security FROM PUBLIC;
