CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_v3_issuers_v3_rotation ON v3_issuers (expires_at) WHERE version = 3 AND expires_at IS NOT NULL;
