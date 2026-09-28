-- A CHECK that evaluates to NULL passes. The request binding and the
-- approved-mode checks compared JSON fields that may be missing, so a binding
-- without an identity field, or an approved request without a mode, was
-- accepted. Both are now wrapped in IS TRUE and named.
ALTER TABLE mcpwarden_security.requests DROP CONSTRAINT requests_check1;
ALTER TABLE mcpwarden_security.requests ADD CONSTRAINT requests_binding_identity CHECK ((jsonb_typeof(binding) = 'object'
    AND binding->>'id' = request_id::text
    AND binding->>'boot_id' = boot_id::text
    AND binding#>>'{scope,owner_id}' = owner_id) IS TRUE);
ALTER TABLE mcpwarden_security.requests DROP CONSTRAINT requests_check4;
ALTER TABLE mcpwarden_security.requests ADD CONSTRAINT requests_approved_mode CHECK ((state <> 'approved'
    OR (binding->>'mode' = 'confirm' AND authorization_source = 'owner_confirmation' AND lease_id IS NULL)) IS TRUE);
