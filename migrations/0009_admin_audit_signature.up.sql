-- A unique hash of each admin request's signature, so a replayed signed
-- request fails instead of repeating its change. Rows from calls made
-- without a signed request hold NULL.
ALTER TABLE issuer_admin_audit ADD COLUMN signature_sha256 text NULL;
ALTER TABLE issuer_admin_audit ADD CONSTRAINT issuer_admin_audit_signature_uniq UNIQUE (signature_sha256);
