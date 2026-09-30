-- v3_issuers is deliberately not altered: during a rolling deploy, old pods
-- scan `SELECT i.*` from it into a fixed column list.
CREATE TABLE issuer_retirements (
  issuer_id                uuid PRIMARY KEY REFERENCES v3_issuers(issuer_id),
  replacement_issuer_id    uuid NOT NULL REFERENCES v3_issuers(issuer_id),
  stop_issuing_at          timestamptz NOT NULL,
  expires_at_before_retire timestamp NULL,
  retired_by               text NOT NULL,
  created_at               timestamptz NOT NULL DEFAULT now(),
  CHECK (issuer_id <> replacement_issuer_id)
);
CREATE INDEX issuer_retirements_replacement_idx ON issuer_retirements(replacement_issuer_id);

CREATE TABLE issuer_admin_audit (
  id         bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  operator   text NOT NULL,
  action     text NOT NULL,
  issuer_id  uuid NULL REFERENCES v3_issuers(issuer_id),
  request    jsonb NOT NULL
);
CREATE INDEX issuer_admin_audit_issuer_idx ON issuer_admin_audit(issuer_id, created_at);
