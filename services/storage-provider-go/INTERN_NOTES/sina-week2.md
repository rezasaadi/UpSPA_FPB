# Sina Week 2

## Implemented DB Schema

Implemented the initial PostgreSQL migration in `internal/db/migrations/001_init.sql`.

Tables:
- `setup`
  - `uid_b64 TEXT PRIMARY KEY`
  - `sig_pk_b64 TEXT NOT NULL`
  - `cid_nonce_b64 TEXT NOT NULL`
  - `cid_ct_b64 TEXT NOT NULL`
  - `cid_tag_b64 TEXT NOT NULL`
  - `k_i_b64 TEXT NOT NULL`
  - `last_pwd_update_time BIGINT NOT NULL DEFAULT 0`
- `records`
  - `suid_b64 TEXT PRIMARY KEY`
  - `cj_nonce_b64 TEXT NOT NULL`
  - `cj_ct_b64 TEXT NOT NULL`
  - `cj_tag_b64 TEXT NOT NULL`

Primary keys provide the uniqueness constraints and lookup indexes needed for Week 2.

## Store Initialization

Implemented `internal/db/db.go`.

Behavior:
- reads `DATABASE_URL` in `New`
- creates a `pgxpool.Pool`
- applies the embedded initial migration on startup
- exposes `NewWithDSN` so integration tests can use an explicit DSN without mutating process environment
- exposes `Close` for pool cleanup

The migration is embedded with Go `embed`, so tests and binaries do not depend on the current working directory to locate SQL files.

## Query Layer

Implemented `internal/db/queries.go`.

Setup methods:
- `PutSetup`
- `GetSetup`
- `GetKi`

Record methods:
- `CreateRecord`
- `GetRecord`
- `UpdateRecord`
- `DeleteRecord`

Password update:
- `ApplyPasswordUpdate`

`ApplyPasswordUpdate` uses one conditional `UPDATE`:
- matches by `uid_b64`
- updates only when `new_timestamp > last_pwd_update_time`
- updates `cid_*`, `k_i_b64`, and `last_pwd_update_time` together
- returns `applied=false` when the user is missing or the timestamp is stale

Because this is a single SQL statement, the state transition is atomic at the database layer.

## Integration Tests

Implemented and expanded `internal/db/db_integration_test.go`.

Covered behavior:
- setup insert succeeds
- duplicate setup insert is ignored
- setup retrieval returns stored values and default timestamp
- `GetKi` returns the stored scalar share
- record create succeeds
- duplicate record create is ignored
- record retrieval returns stored values
- record update changes stored values
- record delete removes the row
- update/delete on missing record return `false`
- password update applies for a newer timestamp
- replayed timestamp is rejected
- replay does not overwrite stored values
- missing setup password update returns `false`

Test environment:
- uses `DATABASE_URL` when provided
- otherwise attempts to start a local Docker-backed Postgres test database via `internal/testutil`
- skips DB integration tests when neither option is available

## Verification

Verified with:

```bash
GOCACHE=/tmp/go-build-cache go test -count=1 ./...
```

Current local caveat:
- Docker-backed DB tests may skip if the current user cannot access `/var/run/docker.sock`.
- With `DATABASE_URL` set to a reachable Postgres instance, the DB tests run against that database.
