-- v3_issuer - new issuer structure
CREATE TABLE v3_issuers(
    issuer_id uuid primary key default uuid_generate_v4(),
    issuer_type text not null,
    created_at timestamp not null default now(),
    expires_at timestamp,
    last_rotated_at timestamp,
    valid_from timestamp not null default now(),
    buffer integer not null default 1,
    days_out integer not null default 1,
    overlap integer not null default 0,
    issuer_cohort integer not null default 1,
    redemption_repository text not null default 'dynamodb',
    version integer default 3,
    max_tokens integer default 40,
    duration text default null,
    constraint issuer_type_uniq unique (issuer_type)
);


-- v3_issuer_keys - holds all sign/redeem keys for issuers v3
CREATE TABLE v3_issuer_keys (
    key_id uuid primary key default uuid_generate_v4(),
    issuer_id uuid references v3_issuers(issuer_id),
    created_at timestamp not null default now(),
    start_at timestamp,
    end_at timestamp,
    signing_key text not null,
    public_key text,
    cohort smallint not null default 1
);
-- lookups will be done on the public key
CREATE index keys_public_key_idx on v3_issuer_keys(public_key);

-- v1 migrations
insert into v3_issuers (
    issuer_id, issuer_type, created_at, expires_at, last_rotated_at, valid_from,
    buffer, days_out, overlap, issuer_cohort, redemption_repository, version, max_tokens)
select
    id, issuer_type, created_at, expires_at, rotated_at, created_at,
    1, 30*3, 0, 1, 'postgres', version, max_tokens
from issuers
where version = 1;

-- v2 migrations
insert into v3_issuers (
    issuer_id, issuer_type, created_at, expires_at, last_rotated_at, valid_from,
    buffer, days_out, overlap, issuer_cohort, redemption_repository, version, max_tokens)
select distinct on (issuer_type)
    id, issuer_type, created_at, expires_at, rotated_at, created_at,
    1, 30, 7, 1, 'dynamodb', version, max_tokens
from issuers
where version = 2
order by issuer_type, expires_at desc;

-- For ads, specifically, 6 variations of the below command were run manually with
-- issuer_cohort = 0 through 5
-- insert into v3_issuers (
--     issuer_id, issuer_type, created_at, expires_at, last_rotated_at, valid_from,
--     buffer, days_out, overlap, issuer_cohort, redemption_repository, version, max_tokens)
-- select distinct on (issuer_type)
--     id, issuer_type || '_' || issuer_cohort as issuer_type, created_at, expires_at, rotated_at, created_at,
--     1, 30, 7, issuer_cohort, 'dynamodb', version, max_tokens
-- from issuers
-- where version = 2 and issuer_cohort = 5
-- order by issuer_type, expires_at desc;

-- keys introduction
insert into v3_issuer_keys (
    issuer_id, created_at, signing_key, cohort)
with
    s1 as (
        select id, v3_issuers.issuer_id, issuers.created_at, signing_key, issuers.issuer_cohort from issuers left join v3_issuers on v3_issuers.issuer_type = issuers.issuer_type
    )
select s1.issuer_id, s1.created_at, s1.signing_key, s1.issuer_cohort from s1;

-- For ads, specifically, this modified keys introduction command was run manually to
-- accomodate the modified issuer_type from the v2 migrations step
-- insert into v3_issuer_keys (
--     issuer_id, created_at, signing_key, cohort)
-- with
--     s1 as (
--         select id, v3_issuers.issuer_id, issuers.created_at, signing_key, issuers.issuer_cohort from issuers left join v3_issuers on v3_issuers.issuer_type  = issuers.issuer_type || '_' || issuers.issuer_cohort
--     )
-- select s1.issuer_id, s1.created_at, s1.signing_key, s1.issuer_cohort from s1;
