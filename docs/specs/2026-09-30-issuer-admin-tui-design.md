# Issuer admin API + `cbp-manage` TUI: design

Date: 2026-09-30

Status: approved in chat, pending spec review

## Goal

Operators can view, create, edit, rotate keys for, and retire issuers from a terminal UI, against the live production service. The service has years of history and outstanding tokens in the wild, so:

- Issuers are **never deleted**. There is no delete path, API or DB helper.
- An issuer is only ever **retired in favor of a replacement**, with an enforced overlap. The old issuer stops issuing and keeps redeeming, and the replacement issues for at least 90 days before the old one stops redeeming.
- All rules are enforced server-side. The TUI is a thin client.

Out of scope for this spec: issued/unredeemed token counts (deferred, since no durable issuance record exists today), rate limiting, replay nonces.

## Prior work

Branches `feature/issuer-management-api` (Jan–Feb 2026) and `feature/issuer-management-api-minimal-cli` contain a management API with a custom `X-Signature` scheme and a `cmd/cbp-manage` CLI. This work starts fresh on `master`, ports useful DB/query logic and test cases from those branches, and replaces the custom signing scheme with the subscriptions support model below. The `cbp-manage` name is kept.

## 1. Authentication and authorization

Modeled on subscriptions `pkg/api/support_keys.go`.

- New file `server/admin_keys.go`:
  - `prodAdminKeys` / `devAdminKeys`: hardcoded maps from OpenSSH `authorized_keys` ed25519 lines to an opaque operator ID (the key comment, which is never an email because the repo is public).
  - `adminKeysForEnv(env)`: `production` → prod keys. `staging`, `development`, `dev`, `sandbox`, `local`, `localtest`, `test` → dev keys (staging is on the dev list so the dark R1 release can be smoke-tested). Any other value → empty allowlist plus a startup warning, so every admin request is denied. Startup never fails on this.
  - A keystore implementing bat-go `httpsignature.Keystore`, keyed by hex raw public key. Unknown key → error.
  - `newAdminSignatureMwr(env)` returns `middleware.VerifyHTTPSignedOnly(httpsignature.ParameterizedKeystoreVerifier{…})` with `Algorithm: ED25519`, `Headers: date, digest, (request-target)`.
- Routes mount under `/v1/admin` on their own chi subrouter, outside the existing `TOKEN_LIST` bearer middleware. The signature middleware applies in **every** environment (unlike `TOKEN_LIST`, which is production-only).
- Authorization is a single role: any allowlisted key can call any admin route. Onboarding/offboarding an operator is a code change + deploy, same as subscriptions.
- Operator identity: handlers resolve `middleware.GetKeyID(ctx)` to the operator ID via the keystore map and record it on every audit row.
- Request bodies are capped at 1 MiB (`http.MaxBytesReader`).

## 2. Data model changes

Migration `migrations/0008_issuer_admin.{up,down}.sql`. Bump `m.Migrate(7)` → `m.Migrate(8)` in `server/db.go`.

**`v3_issuers` is not altered.** `GetLatestIssuer` and `GetLatestIssuerKafka` run `SELECT i.*` and scan exactly 14 columns. Adding a column would break every sign request on old pods during a rolling deploy (the first new pod migrates while old pods still serve). Retirement state therefore lives in its own table:

```sql
CREATE TABLE issuer_retirements (
  issuer_id                uuid PRIMARY KEY REFERENCES v3_issuers(issuer_id),
  replacement_issuer_id    uuid NOT NULL REFERENCES v3_issuers(issuer_id),
  stop_issuing_at          timestamptz NOT NULL,
  expires_at_before_retire timestamp NULL,
  created_at               timestamptz NOT NULL DEFAULT now(),
  CHECK (issuer_id <> replacement_issuer_id)
);
CREATE INDEX issuer_retirements_replacement_idx ON issuer_retirements(replacement_issuer_id);

CREATE TABLE issuer_admin_audit (
  id         bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  operator   text NOT NULL,
  action     text NOT NULL,           -- create | update | retire | cancel_retire
  issuer_id  uuid NULL REFERENCES v3_issuers(issuer_id),
  request    jsonb NOT NULL
);
CREATE INDEX issuer_admin_audit_issuer_idx ON issuer_admin_audit(issuer_id, created_at);
```

`issuer_retirements` does not record who retired an issuer. The operator of a retire is recorded in its `issuer_admin_audit` row.

The stop-redeeming time is the existing `v3_issuers.expires_at` (an existing column, so updating it is safe for old pods). Down migration drops both new tables. No rows exist until an operator acts, so behavior is unchanged on deploy.

`model.Issuer` gains `StopIssuingAt *time.Time`, tagged `json:"-"`. It also gains `func (x *Issuer) IsIssuing(now time.Time) bool`, which is false once `now >= *StopIssuingAt`. `StopIssuingAt` is populated only by `fetchIssuersByCohort` (the sign path) with one PK lookup on cache miss, so the value is cached with the issuer. Admin reads join `issuer_retirements` in their own queries.

Issuer status (derived, never stored):

| status   | condition |
|----------|-----------|
| active   | `stop_issuing_at` NULL, not expired |
| retiring | `stop_issuing_at` set and in the future |
| retired  | `stop_issuing_at` past, not expired (redeem-only) |
| expired  | `expires_at` past (neither issues nor redeems) |

`expires_at` of `0001-01-01` (current "no expiry" encoding) is treated as no expiry, matching existing `HasExpired`.

## 3. Retirement rules

All request times are normalized to UTC before storage. The `v3_issuers` time columns are `timestamp` without time zone, and Postgres drops any offset. Without normalization, that would shift (and could shorten) stored times.

`POST /v1/admin/issuers/{id}/retire` takes `{replacement_issuer_id, stop_issuing_at, stop_redeeming_at}`. The server locks both rows (`SELECT … FOR UPDATE`) in one transaction. It rejects the request with a 422 and a specific message unless all of these hold:

1. Target is not already retiring/retired/expired.
2. `replacement_issuer_id` ≠ target id, exists, is `active` (not retiring, retired or expired). Version may differ (e.g. v2 → v3).
3. `stop_issuing_at >= now`, truncated to the second. A small negative skew of ≤ 60s is clamped to now.
4. `stop_redeeming_at >= stop_issuing_at + 90 days`.
5. v3 target: `stop_redeeming_at >= max(max(end_at) of existing keys, stop_issuing_at + (buffer + overlap) × duration)`. Tokens are signed for future windows, and the rotation cron keeps adding keys until `stop_issuing_at`, so this covers the furthest window that can exist.
6. Replacement stays issuable through the overlap. Its `expires_at` is no-expiry or `>= stop_redeeming_at`.
7. Replacement is already issuable at `stop_issuing_at`. Its `valid_from` is NULL or `<= stop_issuing_at`.
8. Target and replacement names must not be prefixes of one another. Kafka sign lookups match `issuer_type LIKE name || '%'` and prefer the later expiry, so a prefix-related replacement would silently take over and bypass the retirement gate. Admin create rejects such names too.

On success: insert the `issuer_retirements` row (storing the old `expires_at` in `expires_at_before_retire`), set `v3_issuers.expires_at = stop_redeeming_at`, write the audit row.

The chain rule is enforced on any later retire of an issuer X. If X is the replacement for some Y whose `expires_at` is in the future, X's `stop_issuing_at` must be `>= Y.expires_at`, so the overlap promised to Y cannot be cut short.

Follow-up operations:

- `DELETE /v1/admin/issuers/{id}/retire` cancels a retirement. It is allowed only while status is `retiring`. It restores `v3_issuers.expires_at` from `expires_at_before_retire` and deletes the `issuer_retirements` row. This is the only DELETE in this feature, and the audit table keeps the history.
- `POST /v1/admin/issuers/{id}/retire/postpone` `{stop_issuing_at, stop_redeeming_at?}` is the emergency switch. It is allowed on a retiring **or retired** (not expired) issuer. The new `stop_issuing_at` must be later than the current one and not in the past. Stop-redeeming becomes the later of the current value and `stop_issuing_at + 90 days` (or an explicit value that is not shorter and keeps the 90 days). The replacement must still be issuable through the new window. Its expiry must not be earlier, and if it is itself retiring, neither must its own stop-issuing. For v3, stop-redeeming must also cover the furthest key window the cron can create before the new stop-issuing (rule 5, recomputed).
- Extend redemption: `PATCH` with a later `expires_at` (section 4). Shortening is never allowed for any issuer.

## 4. Other mutations

- `POST /v1/admin/issuers` creates an issuer. The body mirrors the existing v1/v2/v3 create requests plus `version`. It reuses `createIssuer`, `createIssuerV2`, `createV3Issuer`. 409 on duplicate `issuer_type`.
- `PATCH /v1/admin/issuers/{id}` changes only `max_tokens` and `expires_at`. `expires_at` must be later than the current value (no-expiry cannot be changed to a date, because that would shorten it). Any other field → 422. `buffer`, `overlap`, `duration`, `version`, `cohort`, `issuer_type` are immutable. Clients size requests by `buffer+overlap`, so changing them means creating a new issuer and retiring the old one.
- **No manual key rotation.** HTTP v1 redeem (`blindedTokenRedeemHandler`) and bulk redeem verify v1/v2 tokens against only the newest key, in `tokens.go:410,506`. Adding a key would make every outstanding token signed by an older key unredeemable over HTTP (Kafka redeem checks all keys). Rotation is done by **replacement**, which means creating a new issuer and retiring the old one. The ≥90-day overlap keeps old tokens redeemable. v3 keys stay cron-driven windows.

Every mutation writes its `issuer_admin_audit` row in the same transaction. Create goes through a new `txCreateV3Issuer(tx, issuer)` extracted from `createV3Issuer` so the insert, keys and audit row share one transaction. After commit, the handler invalidates the in-process issuer cache (`server/cache.go`) on the serving pod. Other pods pick up the change within `CACHE_DURATION_SECS`. Because retirement is expressed as a timestamp compared at request time, a stale cache entry only matters for "retire now" and cancel. The TUI notes this delay.

## 5. Hot-path changes

The changes are minimal and gated purely on `issuer_retirements.stop_issuing_at`, which the sign path loads with the issuer:

- Sign call sites only. `BlindedTokenIssuerHandlerV2` and `blindedTokenIssuerHandler` check after their `GetLatestIssuer` call, and the Kafka sign handler checks after `GetLatestIssuerKafka`. If `!issuer.IsIssuing(now)`, they reject. HTTP returns 400 `issuer is retired; use replacement`. Kafka returns `issuerInvalid`. Sign requests are **rejected, never routed** to the replacement. The client stores tokens under the issuer it asked for, so silently signing with another issuer would make those tokens unredeemable.
- Redemption paths are unchanged. They already stop at `expires_at`.
- `rotateIssuers` (v1/v2) and `rotateIssuersV3` add `AND NOT EXISTS (SELECT 1 FROM issuer_retirements r WHERE r.issuer_id = v3_issuers.issuer_id AND r.stop_issuing_at <= now())`.
- `GetLatestIssuer` itself is not gated. Bulk redeem (`blindedTokenBulkRedeemHandler`) also calls it and must keep redeeming for retired issuers.

## 6. Read API

- `GET /v1/admin/issuers` returns a bare JSON array of all issuers with derived status, version, cohort, max_tokens, created/valid_from/expires/stop_issuing, replacement id, key count, latest key end.
- `GET /v1/admin/issuers/{id}` returns the above plus keys (`key_id`, `public_key`, `cohort`, `created_at`, `start_at`, `end_at`) and the issuer it is replaced by. It does not list the issuers it replaces. **Signing keys are never serialized** by any admin response type. Admin responses use separate response structs and never reuse `model.IssuerKeys` JSON.
- `GET /v1/admin/audit?issuer_id=&limit=` returns a bare array of entries, newest first, default 100. `issuer_id` is required.

Admin key SELECTs read `key_id` (the existing hot-path SELECTs omit it and are left alone).

Key ordering on the sign/redeem paths is not changed. HTTP redeem verifies v1/v2 tokens against the newest key only, so any change to which key is "last" could strand outstanding tokens (see §4).

## 7. TUI: `cmd/cbp-manage`

Go, `charmbracelet/bubbletea` + `bubbles` + `lipgloss` (new deps). Request/response types and the request signer live in a small cgo-free package `adminapi/` shared by server and TUI, so the TUI builds without the Rust ristretto library. Config: `--url` / `CBP_ADMIN_URL`, `--private-key` / `CBP_ADMIN_PRIVATE_KEY` (OpenSSH ed25519, no passphrase, parsed with `ssh.ParseRawPrivateKey`), matching support-cli. Request signing is a hand-rolled copy of support-cli's `signSupportRequest` (Date, Digest, Signature headers). The client does not use bat-go.

Screens:

1. **Issuer list**: a table of name, version, cohort, status (colored), expires, stop issuing, replacement. Filter by typing, `r` refresh.
2. **Detail**: fields, keys table, retirement chain (replaced by), recent audit.
3. **Create**: a form where version selects which fields are shown.
4. **Edit**: `max_tokens`, `expires_at` (extend only). The client pre-validates, and the server is authoritative.
5. **Replace**: a shortcut into the retire wizard, offering to create the replacement first.
6. **Retire wizard**: pick a replacement from active issuers, or jump to Create and come back. Set stop-issuing (default now) and stop-redeeming. Stop-redeeming defaults to stop-issuing + 90d, or for v3 the later of that and max key end. Then review.

Every mutation ends on a confirm screen showing the exact JSON request. Retire and cancel-retire additionally require typing the issuer name. Server errors are shown verbatim.

## 8. Error handling

- 401/403/408/425 from the signature middleware surface in the TUI with a hint (unknown key vs clock skew).
- Validation failures: 422 with one message naming the violated rule.
- Not found: 404. Duplicate name: 409.
- All DB mutations run in a single transaction. Any error rolls back everything, including the audit insert. The existing `createV3Issuer` deferred-rollback bug that can mask the insert error (`db.go:858-864`) is fixed where we call it.

## 9. Testing

- `server/admin_keys_test.go`: env selection fails closed, keystore lookup, and a request signed like support-cli passes while a tampered path/body/date fails.
- `server/admin_test.go` (`//go:build db`, runs under `make docker-test`): each retirement rule 1–6 and the chain rule, cancel-before/after, extend/shorten, immutable fields, audit row written and rolled back on failure, signing keys absent from responses.
- Hot-path: sign rejected after `stop_issuing_at` (HTTP + Kafka handler), redemption still accepted until `expires_at`, rotation crons skip retired.
- `cmd/cbp-manage`: signer test (round-trip against the server middleware) and bubbletea model tests for the retire wizard defaults and confirm gating. No terminal snapshot tests.

## Rollout

There are three releases, detailed in `docs/issuer-admin-rollout.md`. R0 adds a migration guard so older images survive a newer schema. The guard (`migrateSchema`) only migrates up and skips when the DB is at or past the build's `schemaVersion`. R1 ships this feature with `prodAdminKeys` empty, so it is dark. R2 adds operator keys. The `txCreateV3Issuer` extraction is a pure refactor, so existing create endpoints behave identically.

## Coordination

Another branch (`feat/act-credit-tokens`) is in flight. It uses its own `migrations/act/` directory, so no migration number clash, but it edits `server/tokens.go`, `server/cache.go` and `model/issuer.go`. Changes here to those files are kept to the minimum listed in section 5.
