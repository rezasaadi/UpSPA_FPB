# Sina Week 1

## Proposed Schema

For Week 1, I propose two PostgreSQL tables for the DB layer: `setup` and `records`.

### setup

Purpose: stores one setup row per user.

Columns:
- `uid_b64 TEXT PRIMARY KEY`
- `sig_pk_b64 TEXT NOT NULL`
- `cid_nonce_b64 TEXT NOT NULL`
- `cid_ct_b64 TEXT NOT NULL`
- `cid_tag_b64 TEXT NOT NULL`
- `k_i_b64 TEXT NOT NULL`
- `last_pwd_update_time BIGINT NOT NULL DEFAULT 0`

Rationale:
- `uid_b64` uniquely identifies the user setup row.
- `sig_pk_b64` stores the user’s Ed25519 public key.
- `cid_*` fields store the opaque encrypted credential blob exactly as received.
- `k_i_b64` stores the TOPRF scalar share.
- `last_pwd_update_time` is required for replay protection of password updates.

### records

Purpose: stores encrypted records by record identifier.

Columns:
- `suid_b64 TEXT PRIMARY KEY`
- `cj_nonce_b64 TEXT NOT NULL`
- `cj_ct_b64 TEXT NOT NULL`
- `cj_tag_b64 TEXT NOT NULL`

Rationale:
- `suid_b64` uniquely identifies each stored record.
- `cj_*` fields store the opaque encrypted record blob exactly as received.

This schema matches the expected Week 2 migration targets and keeps the DB layer simple and aligned with the project contract.

## Unique Constraints and Indexes

I plan to use these uniqueness rules:

- `setup.uid_b64` is the primary key, so each user can have only one setup row.
- `records.suid_b64` is the primary key, so each record identifier can appear only once.

Index plan:
- The primary keys already create indexes on `uid_b64` and `suid_b64`.
- These indexes should be sufficient for the initial version because the expected access pattern is direct lookup by exact identifier.
- I do not currently propose extra secondary indexes for Week 1, because no range scans or multi-column filtering requirements are defined yet.

This keeps the initial schema minimal while still supporting correctness and fast lookup.

## Replay Protection Approach

Replay protection is required by the shared contract. The database must store `last_pwd_update_time` per user and reject password updates when:

- `timestamp <= last_pwd_update_time`

Approach:
- `last_pwd_update_time` will live in the `setup` table.
- Every password update request will compare the incoming timestamp against the stored timestamp.
- Only strictly newer timestamps will be accepted.
- If the incoming timestamp is older or equal, the update will be rejected as a replay.

This rule should map to the API behavior that stale password updates are rejected with conflict semantics.

## Password Update Transaction Plan

The password update operation must be atomic.

The DB layer should expose an operation similar to:
- `ApplyPasswordUpdate(uid, ts, cidNonceNew, cidCtNew, cidTagNew, kINew)`

Planned transaction flow:
1. Begin a transaction.
2. Find the target `setup` row by `uid_b64`.
3. Check whether the user exists.
4. Check whether the new timestamp is strictly greater than `last_pwd_update_time`.
5. If valid, update all of the following in the same transaction:
   - `cid_nonce_b64`
   - `cid_ct_b64`
   - `cid_tag_b64`
   - `k_i_b64`
   - `last_pwd_update_time`
6. Commit the transaction.

Failure behavior:
- If the user does not exist, return `applied = false`.
- If the timestamp is stale or replayed, return `applied = false`.
- If any DB error occurs, rollback and return the error.

Correctness note:
- To avoid races under concurrency, the final implementation should use a conditional update strategy such as:
  - update only when `new_timestamp > last_pwd_update_time`
  - then inspect affected row count

This matches the project’s Week 4 DB correctness goal.

## Integration Testing Plan

I plan to write DB integration tests against PostgreSQL.

Main test areas:
- setup insertion works correctly
- setup uniqueness is enforced
- record creation works correctly
- record uniqueness is enforced
- missing-record update returns a not-found style result
- password update accepts strictly newer timestamps
- password update rejects replayed or stale timestamps

Environment plan:
- Initially, tests may run against a local PostgreSQL DSN if needed.
- The proper target is a reusable testcontainers-based PostgreSQL harness.
- In Week 3, I plan to move integration tests to `internal/testutil/postgres.go` so tests can start an ephemeral Postgres container automatically and clean it up after execution.

Expected benefit:
- repeatable DB tests
- no manual shared database dependency
- easier validation of schema and transaction behavior

## Notes for Week 2

Based on this plan, the next implementation step will be:
- `internal/db/migrations/001_init.sql`
- `internal/db/db.go`
- `internal/db/queries.go`
- `internal/db/db_integration_test.go`

Week 2 will convert this design into actual migrations, store methods, and DB tests.