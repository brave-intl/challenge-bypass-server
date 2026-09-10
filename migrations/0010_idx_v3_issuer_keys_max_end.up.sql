CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_v3_issuer_keys_max_end ON v3_issuer_keys (issuer_id, end_at DESC NULLS LAST);
