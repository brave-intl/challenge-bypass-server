# Issuer admin API: rollout and rollback runbook

Covers shipping the issuer admin API, `cbp-manage` TUI and issuer retirement
(spec: `docs/superpowers/specs/2026-09-30-issuer-admin-tui-design.md`) to a
live service with outstanding tokens, with no downtime and a tested way back
at every step.

## Summary

| Release | Contents | Schema | Behavior change | Rollback |
|---|---|---|---|---|
| **R0** | Migration guard in `InitDB` | none | none | previous image, always safe |
| **R1** | Feature code + migration 0008, **prod operator allowlist empty** (staging uses the dev list) | +2 tables | none until an issuer is retired; admin API denies everything in prod | R0 image, safe |
| **R2** | Operator public keys added to `prodAdminKeys` | none | admin API usable in prod | R1 image, safe |

Each release goes staging → production and bakes before the next one starts.

## Why three releases

- **R0 exists because rollback is otherwise an outage.** Today `InitDB` calls
  `m.Migrate(7)`. golang-migrate first checks that the database's *current*
  version exists in the image's migration files (`migrate.go:404`). Once the
  DB is at 8, any pod on an image without `0008_*` files panics at startup,
  and that includes a rollback. R0 skips migrating when the DB is already at
  or past the image's target, so every image from R0 onward can run against a
  newer schema.
- **R1 ships dark.** Schema, sign gate and admin routes deploy with no
  operator able to act in prod. Any regression comes from the deploy itself
  and not from an operator action.
- **R2 is a key list change only.** It turns the feature on.

## Before any release

- [ ] List **every** workload that runs this image: HTTP server, Kafka
      consumers (same binary, `KAFKA_ENABLED`), and any CronJobs. Each one
      runs `InitDB` at startup. A release is "fully rolled out" only when
      all of them run it.
- [ ] Confirm the rollout strategy keeps old pods serving until new pods are
      Ready (`maxUnavailable: 0`).
- [ ] Confirm the exact `ENV` value in staging and production. The admin
      allowlist keys off `production` (prod list) and `staging` (dev list).
      Any other value denies all admin requests. That is safe, but the
      smoke tests would fail.
- [ ] Add at least one operator's key to `devAdminKeys` in R1, so the
      staging smoke test can run.
- [ ] Note the current production values of `CACHE_ENABLED` and
      `CACHE_DURATION_SECS`, which set retirement propagation delay (see R2).
- [ ] Coordinate with the ACT credit-token branch. It carries its own
      migration set (`migrations/act/`). If it also migrates at startup, it
      needs the same guard as R0.

---

## R0: migration guard

**Change** (`server/db.go`, `InitDB`):

```go
const schemaVersion = 7 // bumped to 8 in R1

v, dirty, verr := m.Version()
if verr == nil && !dirty && v >= schemaVersion {
	logger.Info("database schema at or ahead of this build; skipping migrations",
		"db_version", v, "build_version", schemaVersion)
} else if err = m.Migrate(schemaVersion); err != migrate.ErrNoChange && err != nil {
	panic(err)
}
```

**Roll forward**
1. Deploy to staging and confirm the startup log reads
   `db_version=7 build_version=7` and the skip message appears.
2. Deploy to production and confirm the same log on every workload.
3. Bake for 24h. Watch the standard dashboards: sign/redeem rate, error
   metrics, Kafka consumer lag.

**Rollback:** redeploy the previous image. The schema is unchanged (DB still
at 7), so the old `m.Migrate(7)` is a no-op. Always safe.

**Exit criteria:** R0 runs on every workload in production.

---

## R1: feature, dark

**Contents:** migration `0008_issuer_admin` (creates `issuer_retirements` and
`issuer_admin_audit`; `v3_issuers` untouched), `schemaVersion = 8`, admin
routes, sign-path gate, rotation-cron `NOT EXISTS` filter, `prodAdminKeys`
empty.

### Pre-flight (production)

- [ ] Take a DB snapshot. The change is additive, but take it anyway.
- [ ] `SELECT version, dirty FROM schema_migrations;` → `7, false`.
- [ ] Check for long transactions touching issuers:
      `SELECT pid, now() - xact_start, query FROM pg_stat_activity WHERE xact_start < now() - interval '1 minute';`
      The migration's foreign keys take a lock on `v3_issuers` that briefly
      blocks writes (the rotation cron) but not reads (signing and
      redeeming). It waits for any open writer, so start when nothing long
      is running.

### Roll forward

1. **Staging deploy.** Then run this smoke test with a **dev** key using
   `cbp-manage`:
   1. `cbp-manage --whoami` prints your email.
   2. Create two throwaway issuers `rollout-a` / `rollout-b`, retire A → B
      with stop issuing now + 5 min, then cancel. Audit shows
      create/create/retire/cancel_retire.
   3. Retire A → B with stop issuing now. A sign request for `rollout-a`
      returns 400 over HTTP and `issuerInvalid` over Kafka. A redeem of a
      token issued earlier still succeeds.
2. **Production deploy** of the same image.
3. **Verify, per workload, as pods come up:**
   - The startup log shows migration 8 applied once; later pods log the skip.
   - `SELECT version, dirty FROM schema_migrations;` → `8, false`.
   - `SELECT count(*) FROM issuer_retirements;` → `0`.
   - Unsigned `GET /v1/admin/issuers` → `401`. Signed with any key → `403`,
     because the prod allowlist is empty.
   - Sign/redeem rates, error metrics and Kafka lag match the pre-deploy
     baseline.
4. Bake for 24h.

### Rollback triggers

Roll back without further diagnosis if any of these happen:
- a crashloop in any workload;
- `schema_migrations.dirty = true`;
- sign or redeem error rate above baseline;
- Kafka consumer lag growing.

### Rollback procedures

**A. Application rollback (default).** Redeploy the R0 image. R0 sees DB
version 8 ≥ its target 7 and skips migrating. The two new tables stay and
nothing reads them. There is no data change and no downtime.

**R0 is a safe rollback target only while `issuer_retirements` is empty**
(always true during R1, since nobody can act in prod). Once retirements
exist, R0 has no sign gate and no cron filter: retired issuers would start
signing again, and the v3 rotation cron would add key windows past their
already shortened `expires_at`, producing tokens that expire before their
window ends. After R2, roll back to R1 or later. Check first with
`SELECT count(*) FROM issuer_retirements;`.

**B. Migration failed (dirty = true).** Migration 0008 is one multi-statement
file, which Postgres runs atomically, so a failure leaves the schema as it
was and only the dirty flag set. New pods refuse to start and old pods keep
serving.
1. Confirm the tables were not created: `\dt issuer_*`.
2. Run `migrate -path migrations -database "$DATABASE_URL" force 7`.
3. Redeploy the R0 image (or fix the migration and retry).

**C. Remove the schema (only if the new tables themselves cause a
problem).** Run this only after procedure A has put R0 everywhere.
1. Export any rows first:
   `\copy issuer_retirements TO 'retirements.csv' CSV HEADER` and
   `\copy issuer_admin_audit TO 'audit.csv' CSV HEADER`.
2. From an R1 checkout, run
   `migrate -path migrations -database "$DATABASE_URL" goto 7`.
   This drops both tables.
3. R0's guard now sees 7 = 7 and continues as before.

---

## R2: enable operators

**Contents:** operator `authorized_keys` lines in `prodAdminKeys`
(`server/admin_keys.go`). Nothing else.

### Roll forward
1. Deploy to staging and production.
2. Each operator runs `cbp-manage --whoami` against production.
3. Read-only first day: list and inspect issuers only.

### Rollback
Redeploy the R1 image, which has an empty allowlist. Existing retirements
stay in force because the sign gate is in R1. Do not go back to R0 once any
retirement exists (see R1 rollback A). See "Operator actions" to
undo a retirement.

### Retirement propagation
With caching enabled, a retirement that starts **now**, or a cancel/postpone,
reaches each pod within `CACHE_DURATION_SECS`. Scheduling `stop_issuing_at`
in the future avoids that window entirely. Prefer it.

---

## Operator actions: safe use and undo

Retiring is the only operator action that can interrupt clients. A client
still requesting a retired issuer after `stop_issuing_at` gets its sign
requests rejected.

**Before retiring**
1. Create the replacement issuer.
2. Switch client configuration (bat-go SKU issuer names, ads config) to the
   replacement.
3. Watch `crypto_tokens_issued_by_issuer_counter{issuer_type="<old>"}` in
   Prometheus. It should fall to zero as clients move over.
4. Retire with `stop_issuing_at` in the future, at least one cache period
   out, and preferably a day.

**Undo, depending on state**

| State | Undo |
|---|---|
| retiring (before `stop_issuing_at`) | `c` cancel retirement. Restores the original expiry. |
| retired (after `stop_issuing_at`), clients broke | **Postpone**: set a later `stop_issuing_at`. Issuing resumes within the cache period. Stop-redeeming is pushed out to keep ≥ 90 days if needed. Never shortens anything. |
| need longer redemption | Edit, then extend `expires_at`. |
| admin API unavailable, clients broke (break-glass) | Run the SQL below. |

Break-glass SQL, which resumes issuing for one issuer without a deploy:

```sql
BEGIN;
SELECT 1 FROM v3_issuers WHERE issuer_id = '<issuer uuid>' FOR UPDATE;
UPDATE issuer_retirements
   SET stop_issuing_at = now() + interval '30 days'
 WHERE issuer_id = '<issuer uuid>';
INSERT INTO issuer_admin_audit (operator, action, issuer_id, request)
VALUES ('<your email>', 'postpone_breakglass', '<issuer uuid>',
        '{"reason": "<why>"}');
COMMIT;
```

It takes effect within `CACHE_DURATION_SECS`. `expires_at` (stop redeeming)
is unchanged, so right afterwards extend it with the TUI's Edit so that it
is at least:
- the new `stop_issuing_at` + 90 days, and
- for v3 issuers, the new `stop_issuing_at` + (buffer + overlap) ×
  duration. Tokens are signed for future windows, and the cron keeps
  adding them until the new stop time.

The admin postpone endpoint does both automatically. Prefer it whenever the
API is up.
