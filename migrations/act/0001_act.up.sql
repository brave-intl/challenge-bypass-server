-- Anonymous Credit Tokens (ACT). These migrations are tracked in
-- act_schema_migrations, so their versions never collide with the main
-- migrations.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- act_issuers has one row and keypair per credit pool, for example
-- leo-premium-2026-10.
CREATE TABLE act_issuers (
    issuer_id uuid primary key default uuid_generate_v4(),
    name text not null unique,
    -- "organization:service:deployment:version", the ACT domain separator
    params text not null,
    -- credential context, bound into every credential and revealed on spend
    context text not null,
    private_key bytea not null,
    public_key bytea not null,
    -- most credits a single issuance may carry (L = 32 -> max 2^32 - 1)
    max_credits bigint not null check (max_credits > 0 and max_credits <= 4294967295),
    created_at timestamptz not null default now(),
    -- optional time after which /issue and rollovers into this issuer stop.
    -- Existing credentials can still be spent until expires_at.
    stop_issuing_at timestamptz,
    expires_at timestamptz not null,
    check (stop_issuing_at is null or stop_issuing_at <= expires_at)
);

-- act_issuer_rollovers lists the source issuers that each target issuer
-- accepts rollovers from. Rolling over credentials of the target issuer
-- itself needs no row.
CREATE TABLE act_issuer_rollovers (
    target_issuer_id uuid not null references act_issuers(issuer_id),
    source_issuer_id uuid not null references act_issuers(issuer_id),
    created_at timestamptz not null default now(),
    primary key (target_issuer_id, source_issuer_id),
    check (target_issuer_id <> source_issuer_id)
);

-- act_spends has one row per nullifier. The row records the spend, which
-- stops a double spend, and its state: held then refunded, or rolled_over.
-- spend_proof (about 4.9 KB) is kept only while the row is held. proof_hash
-- and idempotency_key are kept permanently, so an origin can retry safely.
CREATE TABLE act_spends (
    issuer_id uuid not null references act_issuers(issuer_id),
    nullifier bytea not null check (octet_length(nullifier) = 32),
    proof_hash bytea not null check (octet_length(proof_hash) = 32),
    idempotency_key text not null check (idempotency_key <> ''),
    spend_proof bytea,
    charge bigint not null check (charge > 0 and charge <= 4294967295),
    cost bigint check (cost is null or (cost >= 0 and cost <= charge)),
    refund bytea,
    status text not null default 'held' check (status in ('held', 'refunded', 'rolled_over')),
    created_at timestamptz not null default now(),
    refunded_at timestamptz,
    primary key (issuer_id, nullifier),
    check (
        (status = 'held' and spend_proof is not null and cost is null and refund is null and refunded_at is null) or
        (status = 'refunded' and spend_proof is null and cost is not null and refund is not null and refunded_at is not null) or
        (status = 'rolled_over' and spend_proof is null and cost = charge and refund is null and refunded_at is not null)
    )
);

-- the sweeper scans only abandoned holds
CREATE INDEX act_spends_held_idx ON act_spends (created_at) WHERE status = 'held';

-- act_issuances stores each /issue and /rollover response by idempotency key.
-- A retry after a lost response gets the same response, so rolled-over
-- credits are not lost and purchased credits are not minted twice.
CREATE TABLE act_issuances (
    issuer_id uuid not null references act_issuers(issuer_id),
    idempotency_key text not null check (idempotency_key <> ''),
    request_hash bytea not null check (octet_length(request_hash) = 32),
    purchased_credits bigint not null check (purchased_credits >= 0 and purchased_credits <= 4294967295),
    rolled_credits bigint not null check (rolled_credits >= 0 and rolled_credits <= 4294967295),
    total_credits bigint not null check (total_credits > 0 and total_credits <= 4294967295 and total_credits = purchased_credits + rolled_credits),
    response bytea not null,
    created_at timestamptz not null default now(),
    primary key (issuer_id, idempotency_key)
);
