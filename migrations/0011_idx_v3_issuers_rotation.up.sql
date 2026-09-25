CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_v3_issuers_rotation ON v3_issuers (version, expires_at) WHERE expires_at IS NOT NULL;
