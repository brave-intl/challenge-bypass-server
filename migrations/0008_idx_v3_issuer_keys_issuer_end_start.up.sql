CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_v3_issuer_keys_issuer_end_start ON v3_issuer_keys (issuer_id, end_at ASC NULLS FIRST, start_at ASC) INCLUDE (signing_key, public_key, cohort, created_at);
