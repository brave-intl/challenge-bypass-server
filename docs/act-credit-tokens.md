# Anonymous Credit Tokens (ACT)

Pay-per-use credits (e.g. per LLM token) that the client spends anonymously.
Built on [draft-schlesinger-cfrg-act] and [draft-schlesinger-privacypass-act],
using Google's [`anonymous-credit-tokens`] crate pinned to **0.4.2**.

> **Warning:** the upstream crate is experimental and unaudited, and both drafts
> are individual submissions. Get a security review before serving production
> traffic.

ACT sits alongside the existing VOPRF tokens (`/v1`–`/v3`) and doesn't change them.

## Contents

1. [How it works](#how-it-works)
2. [Roles](#roles)
3. [Client guide](#client-guide)
4. [Service (origin) guide: pay-per-token inference](#service-origin-guide-pay-per-token-inference)
5. [HTTP API](#http-api)
6. [Wire formats and parameters](#wire-formats-and-parameters)
7. [Operating it](#operating-it)

## How it works

A **credential** holds a hidden balance of credits. Only the client can read the
balance; the server never learns it and can't link one spend to the next.

Each request:

1. **Hold.** The client proves it can pay `hold` credits and sends the proof.
   The server verifies it and records the proof's **nullifier**, which is how
   double spends are stopped.
2. **Use.** The service does the work, capped at what the hold covers.
3. **Settle.** The service reports the actual `cost`. The server issues a
   **refund** of `hold - cost`.
4. **Continue.** The client combines the refund with its secret state to get
   its next credential, holding `balance - cost`.

```
client                      service (e.g. Leo)                  cbp
  | proof(hold=4000) ---------> |                                  |
  |                             | POST /spend {proof} -----------> | verify, record nullifier
  |                             | <-------------- {nullifier, held}|
  |                             |  run inference (<= hold)         |
  |                             | POST /spend/{n}/refund {cost} -> | refund = hold - cost
  | <---------- stream ... refund (last event) <------------------ |
  | next credential = balance - cost                                |
```

## Roles

| Role | Holds | Talks to |
|---|---|---|
| **Client** (browser) | the credential and its secret state | the service only |
| **Service** (Leo backend, SKU service) | nothing secret | cbp, over the authenticated API |
| **cbp** (this server) | issuer private keys, nullifiers, holds and refunds | services |

Clients never call cbp directly. Every ACT route sits behind the same bearer-token
auth as the other cbp routes.

## Client guide

### 1. Fetch issuer parameters

The service gives the client, or proxies from `GET /v1/act/issuer/{name}`:

- `params`: the ACT domain separator string (see [below](#wire-formats-and-parameters))
- `public_key`: the issuer public key (base64 CBOR)
- `max_credits`, `expires_at`, `credit_bits` (32)

Pin these per issuer. Treat any change to `params` or `public_key` as a new issuer.

### 2. Get a credential

```
(pre, request) = PreIssuance.random(); request = pre.request(params)
-> send `request` to the service, which calls POST /v1/act/issuer/{name}/issue
<- response
credential = pre.to_credit_token(params, public_key, request, response)
```

`to_credit_token` verifies the issuer's proof. If it fails, discard everything
and retry from the start. Store `credential` securely. Delete `pre` once
finalized.

### 3. Spend (every request)

```
(proof, prerefund) = credential.prove_spend(params, hold)
```

- **Delete the old `credential` immediately.** Once `proof` exists, the
  credential is spent even if the request never arrives: reusing it gets a
  409 (double spend).
- **Persist `(proof, prerefund)` before sending.** They're the only way to
  recover the balance if the response is lost.
- `hold` must be ≤ the credential's balance. Use the **fixed hold size for the
  model** (see [Privacy](#privacy-rules)), not a per-request estimate.

### 4. Finish with the refund

The service returns the refund, typically as the last event of the response
stream:

```
credential = prerefund.to_credit_token(params, proof, refund, public_key)
```

Then delete `proof` and `prerefund`.

### 5. Recover from a lost response

If the connection drops before the refund arrives, ask the service to fetch
`GET /v1/act/issuer/{name}/spend/{nullifier}`. The nullifier is the hex value
the service returned from `/spend`. Or, if you never got one, just retry the
spend: resending the **identical** proof is idempotent and returns the current
state.

- `status: "held"`: not settled yet. Retry later. The server settles abandoned
  holds at **cost 0** after `ACT_HOLD_TIMEOUT` (default 15 min), so the full hold
  comes back.
- `status: "refunded"`: finish step 4 with the returned `refund`.

Only the holder of `prerefund` can use a refund, so exposing it by nullifier is
safe.

### Concurrency and multiple devices

- **One request in flight per credential.** A credential is a chain: each spend
  consumes it and the refund produces the next one. For parallel requests (tabs,
  agents) get several smaller credentials and give each concurrent request its
  own.
- **Don't sync one credential across devices.** Two devices holding the same
  credential race: the first spend wins, and the second gets a 409 until it
  receives the newer credential. Credentials can't be split or merged. Give each
  device its own credential, issued from the account's allowance by the SKU
  service.
- **Top-ups** are new credentials. The client chooses which one to spend from.

### Privacy rules

- **Use fixed hold sizes** (e.g. "model X holds 4,000 credits"). The hold amount
  is visible to the server, and holds chosen freely per request split users into
  small groups that are easier to link.
- **`context` is visible on every spend.** Issuers must use one context per
  pool or epoch, never one per user (the server enforces one per issuer).
- **Draining a credential is visible.** Spending an odd remainder (smaller than
  the standard hold) reveals a low balance. Prefer letting the remainder expire,
  or accept the leak only at the end of a chain.

### Client libraries

- Rust: [`anonymous-credit-tokens`] **=0.4.2** (brave-core can use it directly).
  Use `L = 32` (the const generic) everywhere.
- TypeScript: [`act-ts`] (check wire compatibility with 0.4.2 before use).
- Go reference: `act.Client*` functions in this repo (`act/cgo.go`), used by the
  tests in `server/act_test.go`.

## Service (origin) guide: pay-per-token inference

1. **Price in credits.** Example: 1 credit = 1 output token on the cheapest
   model, and other models are multiples. `cost = in_tokens * rate_in + out_tokens * rate_out`.
2. **Publish a fixed hold per model** and cap `max_tokens` so that the worst-case
   cost is ≤ the hold. The hold is a hard budget.
3. **`POST /spend` before running inference.** Don't start work on anything but
   a 200. The response has `nullifier` and `charge` (the hold).
4. **Settle with `POST /spend/{nullifier}/refund {"cost": n}`** when done, even
   on errors (use `cost: 0` if nothing was served). Send `refund` to the client
   as the last stream event.
5. **Retry settlement on failure.** It's idempotent for the same `cost`. Don't
   change `cost` between retries: that returns 409.

## HTTP API

All bodies are JSON. `[]byte` fields are standard base64 (Go `encoding/json`).
Nullifiers are 64 hex characters. Examples: `api-doc/http/act.http`.

| Method | Path | Body | Success |
|---|---|---|---|
| POST | `/v1/act/issuer` | `{name, max_credits, expires_at, context?, params?}` | 201 issuer |
| GET | `/v1/act/issuer/{name}` | none | 200 issuer |
| POST | `/v1/act/issuer/{name}/issue` | `{request, credits}` | 200 `{response}` |
| POST | `/v1/act/issuer/{name}/spend` | `{proof}` | 200 spend |
| GET | `/v1/act/issuer/{name}/spend/{nullifier}` | none | 200 spend |
| POST | `/v1/act/issuer/{name}/spend/{nullifier}/refund` | `{cost}` | 200 spend |

**Issuer:** `{name, params, public_key, max_credits, credit_bits, created_at, expires_at}`

**Spend:** `{nullifier, status: "held"|"refunded", charge, cost?, refund?, created_at, settled_at?}`

### Errors

| Code | When |
|---|---|
| 400 | malformed body or ACT message, invalid proof (includes wrong issuer or context), credits outside `1..max_credits`, `cost > charge`, issuer expired (issue and spend only) |
| 404 | unknown issuer or nullifier |
| 409 | issuer name exists; nullifier already spent with a different proof (**double spend**); spend already settled with a different `cost` |
| 501 | server built without ACT support (see [Building](#building)) |

Expired issuers still accept `refund` and `GET spend`, so in-flight holds always
settle.

## Wire formats and parameters

- **Messages** (`request`, `response`, `proof`, `refund`, `public_key`) are
  the CBOR encodings from `anonymous-credit-tokens` 0.4.2.
- **`credit_bits` (L) = 32.** Balances and charges must be < 2^32. A spend proof
  is about 4.9 KB (about 6.6 KB base64).
- **`params`** is `organization:service:deployment:version`. Default:
  `brave:challenge-bypass-server:<ENV>:2026-09-30`. It seeds the generators, so
  client and server must use the identical string.
- **Context:** the issuer's `context` string (default: the issuer name) is hashed
  to a scalar (BLAKE3 derive-key `brave challenge-bypass-server ACT credential
  context v1`, wide-reduced) and bound into every credential. Clients don't
  compute it.

Measured on a 16-thread dev box: verifying a spend takes about 5.5–7 ms of server
CPU; proving a spend takes about 4.6 ms on the client (`go test -tags act -bench . ./act/`).

## Operating it

### Building

The crypto is Rust (`act/ffi`), linked through cgo only with the `act` build
tag. Default builds compile a stub, and every ACT route returns 501.

```sh
make act-ffi                     # builds act/ffi/target/release/libcbp_act_ffi.a
go build -tags act .             # links it
go test -tags act ./act/ ./server/   # server tests need DATABASE_URL
```

The Dockerfile doesn't build ACT yet. To ship it, add a stage like:

```dockerfile
FROM rust:1.96 AS act_builder
RUN rustup target add x86_64-unknown-linux-musl && apt-get update && apt-get install -y musl-tools
COPY act/ffi /act
WORKDIR /act
RUN cargo build --release --target x86_64-unknown-linux-musl --locked
# in go_builder:
COPY --from=act_builder /act/target/x86_64-unknown-linux-musl/release/libcbp_act_ffi.a /usr/lib/
# and add `act` to -tags
```

### Configuration

| Env | Default | Meaning |
|---|---|---|
| `ACT_HOLD_TIMEOUT` | `15m` | holds older than this are settled at cost 0 by the minutely sweeper |
| `ENV` | `development` | feeds the default `params` deployment field |

### Storage

- `act_issuers`: one row per issuer (keypair and policy). Private keys are
  stored the same way as the v3 signing keys.
- `act_spends`: one row per nullifier (the double-spend record plus hold/refund
  state). The primary key is `(issuer_id, nullifier)`.
- The schema lives in `migrations/act/`, is embedded in the binary, and is
  tracked in its own `act_schema_migrations` table, so it never collides with
  the main migration numbering.

### Key rotation and retention

- Treat an issuer as an epoch, e.g. `leo-premium-2026-10`. Create the next one
  before `expires_at`. Refunds re-issue under the same key, so a credential chain
  lives exactly as long as its issuer.
- Nullifiers only need to be kept until their issuer expires. There's no cleanup
  job yet. Delete `act_spends` rows for issuers expired longer than the hold
  timeout.

### Metrics

`cbp_api_act_total{action, outcome}`. Actions: `createIssuer`, `getIssuer`, `issue`,
`spend`, `getSpend`, `refund`, `sweep`. Watch `spend{outcome="double_spend"}` and
`sweep{outcome="settled"}` (a rising count means services aren't settling holds).

[draft-schlesinger-cfrg-act]: https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/
[draft-schlesinger-privacypass-act]: https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01
[`anonymous-credit-tokens`]: https://crates.io/crates/anonymous-credit-tokens
[`act-ts`]: https://github.com/thibmeu/act-ts
