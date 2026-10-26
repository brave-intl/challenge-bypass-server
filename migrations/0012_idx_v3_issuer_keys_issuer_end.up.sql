CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_v3_issuer_keys_issuer_end ON v3_issuer_keys USING BTREE (issuer_id, end_at DESC);
