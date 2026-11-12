-- Anonymous Credit Tokens (ACT). Tracked in its own migrations table
-- (act_schema_migrations) so it never collides with the main sequence.

-- act_issuers - one keypair per credit pool/epoch (e.g. leo-premium-2026-10)
CREATE TABLE act_issuers (
    issuer_id uuid primary key default uuid_generate_v4(),
    name text not null unique,
    -- "organization:service:deployment:version", the ACT domain separator
    params text not null,
    -- credential context bound into every credential; revealed on spend
    context text not null,
    private_key bytea not null,
    public_key bytea not null,
    -- most credits a single issuance may carry
    max_credits bigint not null check (max_credits > 0),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

-- act_spends - one row per nullifier: the double-spend record and the
-- hold/refund state machine (held -> refunded)
CREATE TABLE act_spends (
    issuer_id uuid not null references act_issuers(issuer_id),
    nullifier bytea not null,
    spend_proof bytea not null,
    charge bigint not null,
    cost bigint,
    refund bytea,
    status text not null default 'held' check (status in ('held', 'refunded')),
    created_at timestamptz not null default now(),
    refunded_at timestamptz,
    primary key (issuer_id, nullifier)
);

-- the sweeper scans only abandoned holds
CREATE INDEX act_spends_held_idx ON act_spends (created_at) WHERE status = 'held';
