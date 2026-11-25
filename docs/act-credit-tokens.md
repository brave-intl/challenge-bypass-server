# Anonymous Credit Tokens (ACT)

Pay-per-use credits (for example per LLM token) that the client spends anonymously. Built on [draft-schlesinger-cfrg-act] and [draft-schlesinger-privacypass-act], using Google's [`anonymous-credit-tokens`] crate pinned to **0.4.2**.

> **Warning:** the upstream crate is experimental and unaudited, and both drafts are individual submissions. Get a security review before serving production traffic.

ACT sits alongside the existing VOPRF tokens (`/v1` to `/v3`) and does not change them. It is HTTP API-only and gated behind `ACT_ENABLED=true` (default `false`) so binaries built with the `act` tag stay inert until enabled.

## Contents

1. [How it works](#how-it-works)
2. [Roles](#roles)
3. [Client guide](#client-guide)
4. [Service (origin) guide: pay-per-token inference](#service-origin-guide-pay-per-token-inference)
5. [HTTP API](#http-api)
6. [Wire formats and parameters](#wire-formats-and-parameters)
7. [Operating it](#operating-it)
8. [Smoke test](#smoke-test)

## How it works

A **credential** holds a hidden balance of credits. Only the client can read the balance. The server never learns it and cannot link one spend to the next.

Each request:

1. **Hold.** The client proves it can pay `hold` credits and sends the proof. The service forwards the proof along with a unique `idempotency_key` for that request. The server verifies the proof and records its **nullifier**, which blocks double spends and replays.
2. **Use.** The service does the work, capped at what the hold covers.
3. **Settle.** The service reports the actual `cost`. The server issues a **refund** of `hold - cost` and drops the stored spend proof.
4. **Continue.** The client combines the refund with its secret state to get its next credential, holding `balance - cost`.
5. **Rollover or consolidate (optional).** To migrate balances off a retiring/expired issuer or merge small dust remainders into one spendable credential, the client proves full-balance spends of up to 16 unspent credentials and sends them with a fresh `IssuanceRequest` either to standalone anonymous `POST /rollover` (zero new credits minted) or attached to a top-up on `POST /issue`.

```
client                      service (e.g. Leo)                  cbp
  | proof(hold=4000) ---------> |                                  |
  |                             | POST /spend {proof, idemp_key} ->| verify, record nullifier
  |                             | <---------- {nullifier, held}    |
  |                             |  run inference (<= hold)         |
  |                             | POST /spend/{n}/refund {cost} -> | refund = hold - cost
  | <---------- stream ... refund (last event) <------------------ |
  | next credential = balance - cost                                |
```

## Roles

| Role | Holds | Talks to |
|---|---|---|
| **Operator** | Ed25519 admin key | `/v1/admin/act/issuers` (signed HTTP requests) |
| **Client** (browser) | the credential and its secret state | the service only |
| **Billing / SKU service** | `ACT_ISSUE_TOKEN_LIST` bearer token | `/v1/act/issuer/{name}/issue` |
| **Service** (Leo backend) | `TOKEN_LIST` bearer token | `/v1/act/issuer/{name}`, `/rollover`, `/spend`, `/refund` |
| **cbp** (this server) | issuer private keys, nullifiers, holds, refunds, issuances | operators and services |

Clients never call cbp directly. Authorization is split into three tiers: operator Ed25519 keys for creating, listing, and updating ACT issuers (`/v1/admin/act/issuers`), `ACT_ISSUE_TOKEN_LIST` for minting purchased credits (`/issue`), and `TOKEN_LIST` for origin spends, refunds, and zero-minting anonymous rollovers (`/rollover`).

## Client guide

### 1. Fetch issuer parameters

The service gives the client, or proxies from `GET /v1/act/issuer/{name}`:

- `params`: the ACT domain separator string (see [below](#wire-formats-and-parameters))
- `context`: the issuer context string bound into credentials
- `public_key`: the issuer public key (base64 CBOR)
- `max_credits`, `stop_issuing_at`, `expires_at`, `rollover_from`, `credit_bits` (32)

Pin these per issuer. Treat any change to `params` or `public_key` as a new issuer.

### 2. Get a credential

```
(pre, request) = PreIssuance.random(); request = pre.request(params)
-> send `request` to the billing service, which calls POST /v1/act/issuer/{name}/issue
<- response
credential = pre.to_credit_token(params, public_key, request, response)
```

`to_credit_token` verifies the issuer's proof. If it fails, discard everything and retry from the start. Store `credential` securely. Delete `pre` once finalized.

### 3. Spend (every request)

```
(proof, prerefund) = credential.prove_spend(params, hold)
```

- **Delete the old `credential` immediately.** Once `proof` exists, the credential is spent even if the request never arrives. Reusing it gets a 409 (double spend).
- **Persist `(proof, prerefund)` before sending.** They are the only way to recover the balance if the response is lost.
- `hold` must be `<=` the credential's balance. Use the **fixed hold size for the model** (see [Privacy rules](#privacy-rules)), not a per-request estimate.

### 4. Finish with the refund

The service returns the refund, typically as the last event of the response stream:

```
credential = prerefund.to_credit_token(params, proof, refund, public_key)
```

Then delete `proof` and `prerefund`.

### 5. Roll over expiring credentials or consolidate dust

To migrate unspent credits off a retiring or expired issuer onto a new active issuer, or to merge up to 16 small dust credentials into one spendable credential:

```
for each old_credential with balance R_i:
    (proof_i, _) = old_credential.prove_spend(old_params_i, R_i)
(pre, request) = PreIssuance.random(); request = pre.request(target_params)
-> send (request, [(old_issuer_i, proof_i)...]) to POST /v1/act/issuer/{target}/rollover
   (or attach `rollover` to POST /v1/act/issuer/{target}/issue during a paid top-up)
<- response (total_credits = purchased_credits + sum(R_i))
new_credential = pre.to_credit_token(target_params, target_public_key, request, response)
```

Persist `(pre, request, idempotency_key)` until `new_credential` is saved so a dropped HTTP response can be retried safely with the same `idempotency_key`. CBP stores the signed `IssuanceResponse` in `act_issuances` in the same transaction that consumes the old nullifiers, so retries return the exact same response without losing rolled-over credits.

> **Security note on rollover proofs:** `anonymous-credit-tokens` 0.4.2 does not cryptographically bind a `SpendProof` to a specific `IssuanceRequest`. Unlike a normal `/spend` proof (whose refund can only be finalized by the holder of `prerefund`), an unconsumed rollover proof is worth its full balance to anyone who can pair it with their own `IssuanceRequest` and call `/rollover` or `/issue`. Relays (origin and billing services) MUST forward rollover requests over TLS and MUST NOT log or persist request bodies containing rollover proofs.

### 6. Recover from a lost response

If the connection drops before the refund arrives, extract `nullifier` locally from `proof` (for example `proof.nullifier()` or `act.ClientSpendNullifier(proof)`) and ask the service to fetch `GET /v1/act/issuer/{name}/spend/{nullifier}`.

- `status: "held"`: not settled yet. Retry later. The server settles abandoned holds at **cost 0** after `ACT_HOLD_TIMEOUT` (default 15 min), so the full hold comes back.
- `status: "refunded"`: finish step 4 with the returned `refund`.
- `status: "rolled_over"`: nullifier was permanently consumed by a rollover; retry the original `/rollover` or `/issue` request with its `idempotency_key` to recover the signed `IssuanceResponse`.

Only the holder of `prerefund` can use a refund, so exposing it by nullifier is safe. Do not retry a lost client request by submitting the same `proof` as a brand-new origin request, because the origin assigns a fresh `idempotency_key` and cbp rejects that replay with 409.

### Concurrency and multiple devices

- **One request in flight per credential.** A credential is a chain where each spend consumes it and the refund produces the next one. For parallel requests (tabs, agents), get several smaller credentials and give each concurrent request its own.
- **Do not sync one credential across devices.** Two devices holding the same credential race. The first spend wins, and the second gets a 409 until it receives the newer credential. Credentials cannot be split or merged directly, though multiple dust credentials on one device can be consolidated via `/rollover`. Give each device its own credential(s), issued from the account's allowance by the SKU service.
- **Top-ups** are new credentials, optionally rolling dust into the new issuance. The client chooses which credential to spend from.

### Privacy rules

- **Use fixed hold sizes** (for example, "model X holds 4,000 credits"). The hold amount is visible to the server, and holds chosen freely per request split users into small groups that are easier to link.
- **`context` is visible on every spend.** Issuers must use one context per pool or epoch, never one per user. The server enforces one context per issuer.
- **Draining a credential is visible.** Spending an odd remainder (smaller than the standard hold) reveals a low balance. Prefer consolidating dust anonymously via `/rollover` or rolling dust into a top-up.
- **Prefer standalone anonymous `/rollover` over identified top-up rollover when privacy is critical.** Rolling dust into an identified purchase does not link past prompts, because each unspent credential has a fresh unseen nullifier, but it does reveal the remaining balance `R` to the billing service. Standalone `/rollover` avoids linking to user identity entirely.

### Client libraries

- Rust: [`anonymous-credit-tokens`] **=0.4.2** (brave-core can use it directly). Use `L = 32` (the const generic) everywhere.
- TypeScript: [`act-ts`] (check wire compatibility with 0.4.2 before use).
- Go reference: `act.Client*` functions in this repo (`act/cgo.go`), used by the tests in `server/act_test.go`.

## Service (origin) guide: pay-per-token inference

1. **Price in credits.** For example, 1 credit equals 1 output token on the cheapest model, and other models are multiples. `cost = in_tokens * rate_in + out_tokens * rate_out`.
2. **Publish a fixed hold per model** and cap `max_tokens` so that the worst-case cost is `<=` the hold. The hold is a hard budget.
3. **Generate a unique `idempotency_key` per incoming user request** (for example a UUIDv4) and call `POST /spend` with `{proof, idempotency_key}` before running inference. Reuse the same `idempotency_key` only when retrying that exact upstream HTTP call to cbp.
4. **Do not start work unless `POST /spend` returns 200 with `status == "held"`.** If the client replays a proof in a second request, your fresh `idempotency_key` makes cbp return 409. If your own retry hits a hold that was already settled, `status` is `"refunded"` rather than `"held"`. Check `hold_expires_at` so work finishes well before the sweeper settles the hold.
5. **Settle with `POST /spend/{nullifier}/refund {"cost": n}`** when done, even on errors (use `cost: 0` if nothing was served). Send `refund` to the client as the last stream event.
6. **Retry settlement on failure.** It is idempotent for the same `cost`. Do not change `cost` between retries, because that returns 409.
7. **Proxy anonymous `/rollover` for rotation and dust consolidation.** The origin can call `POST /v1/act/issuer/{name}/rollover` using its normal `TOKEN_LIST` bearer token because `/rollover` strictly conserves credits (`purchased_credits = 0`). Do not log or store rollover request bodies, because an unconsumed rollover proof acts as a bearer instrument until CBP consumes its nullifier.

## HTTP API

All bodies are JSON, with unknown fields and trailing data rejected. `[]byte` fields are standard base64 (Go `encoding/json`). Nullifiers are 64 hex characters. Examples live in `api-doc/http/act.http`.

| Method | Path | Auth | Body | Success |
|---|---|---|---|---|
| POST | `/v1/admin/act/issuers` | Ed25519 operator | `{name, max_credits, expires_at, stop_issuing_at?, context?, params?, rollover_from?}` | 201 issuer |
| PATCH | `/v1/admin/act/issuers/{name}` | Ed25519 operator | `{stop_issuing_at?, expires_at?, add_rollover_from?, remove_rollover_from?}` | 200 issuer |
| GET | `/v1/admin/act/issuers` | Ed25519 operator | none | 200 `[issuer]` |
| GET | `/v1/act/issuer/{name}` | `TOKEN_LIST` (prod) | none | 200 issuer |
| POST | `/v1/act/issuer/{name}/issue` | `ACT_ISSUE_TOKEN_LIST` | `{request, credits, idempotency_key, rollover?: [{issuer?, proof}]}` | 200 issuance |
| POST | `/v1/act/issuer/{name}/rollover` | `TOKEN_LIST` (prod) | `{request, idempotency_key, rollover: [{issuer?, proof}]}` | 200 issuance |
| POST | `/v1/act/issuer/{name}/spend` | `TOKEN_LIST` (prod) | `{proof, idempotency_key}` | 200 spend |
| GET | `/v1/act/issuer/{name}/spend/{nullifier}` | `TOKEN_LIST` (prod) | none | 200 spend |
| POST | `/v1/act/issuer/{name}/spend/{nullifier}/refund` | `TOKEN_LIST` (prod) | `{cost}` | 200 spend |

**Issuer:** `{name, params, context, public_key, max_credits, credit_bits, created_at, stop_issuing_at?, expires_at, rollover_from?}`

**Issuance:** `{response, purchased_credits, rolled_credits, total_credits}`

**Spend:** `{nullifier, status: "held"|"refunded"|"rolled_over", charge, cost?, refund?, created_at, hold_expires_at?, settled_at?}`

### Errors

| Code | When |
|---|---|
| 400 | malformed body, unknown JSON field, malformed ACT message, invalid issuer name/params/idempotency_key, invalid proof (includes wrong issuer or context), source issuer not in target's `rollover_from`, more than 16 rollover proofs, total credits outside `1..max_credits`, `cost > charge`, issuer past `stop_issuing_at` (issue and rollover target) or `expires_at` (new spends), shortening `expires_at` on update |
| 401/403 | missing or invalid Ed25519 admin signature (`/v1/admin/act/issuers`) or bearer token (`/v1/act/*`) |
| 404 | unknown issuer, rollover source issuer, or nullifier |
| 409 | issuer name exists; replayed signed admin request; nullifier already spent or rolled over (**double spend / replay**); spend already settled with a different `cost` (or already rolled over); issuance `idempotency_key` reused with a different request |
| 501 | server built without ACT support or `ACT_ENABLED` is not `"true"` |

Expired issuers still accept `refund`, `GET spend`, idempotent retries of pre-expiry spends (matching proof and `idempotency_key`), and **rollover as a source issuer** into any active target issuer that lists them in `rollover_from`.

## Wire formats and parameters

- **Messages** (`request`, `response`, `proof`, `refund`, `public_key`) are the CBOR encodings from `anonymous-credit-tokens` 0.4.2.
- **`credit_bits` (L) = 32.** Balances and charges must be `< 2^32`. A spend proof is about 4.9 KB (about 6.6 KB base64).
- **`params`** is four non-empty `:`-separated fields (`organization:service:deployment:version`), max 256 bytes. Default: `brave:challenge-bypass-server:<ENV>:2026-09-30`. It seeds the generators, so client and server must use the identical string.
- **Context:** the issuer's `context` string (default: the issuer name, max 256 bytes) is hashed to a scalar (BLAKE3 derive-key `brave challenge-bypass-server ACT credential context v1`, wide-reduced) and bound into every credential. Clients do not compute it.

Measured on a 16-thread dev box: verifying a spend takes about 5.5 to 7 ms of server CPU, and proving a spend takes about 4.6 ms on the client (`go test -tags act -bench . ./act/`). Note that `anonymous-credit-tokens` 0.4.2 only verifies inside `refund`, so a full hold+settle cycle currently verifies the proof twice (~12 ms total CPU).

## Operating it

### Building

The crypto is Rust (`act/ffi`), linked through cgo only with the `act` build tag. Default builds compile a stub, and every ACT route returns 501.

`act/ffi` builds **one** static library that bundles `challenge-bypass-ristretto-ffi` (pinned by git rev in `act/ffi/Cargo.toml`) with the ACT bindings. It is installed under the ristretto library's name. Two separate Rust static libraries cannot be linked into one static binary, because each carries its own libstd and they fail with duplicate symbols. **Keep the ristretto rev in `act/ffi/Cargo.toml` in lockstep with `go.mod`.**

```sh
make act-ffi                                           # -> act/ffi/lib/libchallenge_bypass_ristretto_ffi.a
go build -tags act .                                   # links it, no extra flags
ACT_ENABLED=true go test -tags act ./act/ ./server/    # server ACT tests need DATABASE_URL
```

The Docker image builds with ACT by default (`BUILD_TAGS` includes `act`), with `ACT_ENABLED=false` in the runtime image. Build with `--build-arg BUILD_TAGS="osusergo netgo static_build"` to compile out ACT and `/bin/act-smoke` entirely.

### Configuration

| Env | Default | Meaning |
|---|---|---|
| `ACT_ENABLED` | `false` | must be `"true"` to enable `/v1/act/*`, `/v1/admin/act/*`, and the hold sweeper |
| `ACT_ISSUE_TOKEN_LIST` | empty | comma-separated bearer tokens authorized to call `/v1/act/issuer/{name}/issue`; required in `production` (fails closed when empty) |
| `ACT_HOLD_TIMEOUT` | `15m` | holds older than this are settled at cost 0 by the minutely sweeper |
| `ACT_SWEEPER_ENABLED` | `true` | runs in every API process when `ACT_ENABLED=true`, whatever `CRON_ENABLED` says (claims use `SKIP LOCKED`, so replicas do not collide) |
| `ENV` | `development` | feeds the default `params` deployment field and production auth enforcement |

### Storage

- `act_issuers`: one row per issuer (keypair, `stop_issuing_at`, `expires_at`, policy). Private keys are stored the same way as the v3 signing keys. Issuers are read from the writer on cache miss and cached in memory for 30s.
- `act_issuer_rollovers`: operator-configured `(target_issuer_id, source_issuer_id)` pairs permitting cross-issuer rollover.
- `act_spends`: one row per nullifier (double-spend record plus `held`, `refunded`, or `rolled_over` state). Primary key is `(issuer_id, nullifier)`. `spend_proof` (~4.9 KB) is kept only while `status = 'held'` and cleared to `NULL` once refunded (and is always `NULL` for `rolled_over`), leaving only the 32-byte `proof_hash` and `idempotency_key`.
- `act_issuances`: idempotency and crash-recovery records keyed by `(issuer_id, idempotency_key)` storing `request_hash`, `purchased_credits`, `rolled_credits`, `total_credits`, and `response`.
- The schema lives in `migrations/act/`, is embedded in the binary, and is tracked in its own `act_schema_migrations` table via `migrateSchema` (skipping cleanly on rollbacks when the DB is ahead).

### Key rotation and retention

- Treat an issuer as an epoch, for example `leo-premium-2026-10`. To rotate without stranding paid balances: create the replacement issuer `leo-premium-2026-11` via `POST /v1/admin/act/issuers` with `rollover_from: ["leo-premium-2026-10"]`, then set `stop_issuing_at` on `leo-premium-2026-10` via `PATCH /v1/admin/act/issuers/leo-premium-2026-10`. Existing holders keep spending normally until `expires_at` and can roll their remaining balance onto `leo-premium-2026-11` even after `expires_at`.
- Nullifiers must be kept as long as an issuer can still be spent or rolled over from. There is no automated cleanup job yet. Before purging an old issuer's `act_spends` rows, remove it from every target issuer's allowlist via `PATCH /v1/admin/act/issuers/{target}` (`remove_rollover_from`) and wait until after `expires_at` plus `ACT_HOLD_TIMEOUT`.

### Metrics

- `cbp_api_act_total{action, outcome}`: request counts. Actions: `createIssuer`, `updateIssuer`, `listIssuers`, `getIssuer`, `issue`, `rollover`, `spend`, `getSpend`, `refund`, `sweep`, `disabled`. Watch `spend{outcome="double_spend"}` and `sweep{outcome="settled"}` (a rising count means services are not settling holds).
- `cbp_api_act_credits_total{issuer, event}`: credit volume counters recorded on initial state transitions only (not idempotent retries). Events: `issued` (freshly purchased credits only), `rolled_in` (credits migrated via `/rollover` or `/issue` rollover, kept separate so deferred revenue is not double-counted), `held`, `consumed`, `refunded`, `swept`.

## Smoke test

The image ships `/bin/act-smoke` whenever `BUILD_TAGS` includes `act`. Create a smoke issuer via `POST /v1/admin/act/issuers` (or pass `-admin-key` with an authorized operator key), then run:

```sh
/bin/act-smoke -url http://localhost:2416 -issuer act-smoke-2026-10-01 -check-sweep 20m
```

It verifies:

- issuer fetch (or creation with `-admin-key`)
- issue (with `idempotency_key`)
- hold (with `idempotency_key` and `hold_expires_at`)
- idempotent retry (same proof + same `idempotency_key`)
- replay rejection (same proof + different `idempotency_key` -> 409)
- double spend (409)
- refund at actual cost
- recovery by nullifier
- conflicting settle (409)
- spending the refunded credential (cost 0 and full cost `cost == charge`)
- standalone anonymous rollover (`POST /rollover`) preserving balance
- the sweeper settling an abandoned hold at cost 0 (`-check-sweep`)

Every line prints `PASS`, the final line prints `OK: ...`, and the exit code is 0.

### Disabling ACT at runtime

- Unset `ACT_ENABLED` (or set `ACT_ENABLED=false`) to disable all ACT routes (`501`) and stop the sweeper without rebuilding the image.
- Set `ACT_SWEEPER_ENABLED=false` to stop only the sweeper.
- The `act_*` tables are tracked in `act_schema_migrations` and remain inert when ACT is disabled.

[draft-schlesinger-cfrg-act]: https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/
[draft-schlesinger-privacypass-act]: https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01
[`anonymous-credit-tokens`]: https://crates.io/crates/anonymous-credit-tokens
[`act-ts`]: https://github.com/thibmeu/act-ts
