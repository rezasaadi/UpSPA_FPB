# Sina Week 3

## Test Harness

Implemented `internal/testutil/postgres.go` as the DB integration test harness.

The helper:
- starts an ephemeral `postgres:15-alpine` container
- waits for Docker to expose the mapped Postgres port
- returns a `DATABASE_URL`-style DSN with `sslmode=disable`
- returns a cleanup function that terminates the container at the end of the test

The DB integration tests use this helper when `DATABASE_URL` is not set.

Note: the original Week 3 target asks for `testcontainers-go`. Adding that dependency requires `go.mod` and `go.sum` changes, but the `intern/sina` branch guard only allows commits under `internal/db`, `internal/testutil`, and `INTERN_NOTES/sina-*`. Because of that ownership rule, this branch keeps the harness dependency-free and documents the required follow-up. A maintainer-owned dependency update can swap this helper to `testcontainers-go` without changing the DB tests.

## How To Run DB Tests With Docker

From `services/storage-provider-go`:

```bash
go test ./...
```

With Docker available, DB integration tests start their own temporary Postgres container automatically through the Docker CLI.

To run against an existing local Postgres instead:

```bash
DATABASE_URL='postgres://user:password@127.0.0.1:5432/dbname?sslmode=disable' go test ./internal/db
```

## Known Failure Modes

Docker permission errors:
- common message: `permission denied while trying to connect to the Docker daemon socket`
- usually means the current user cannot access `/var/run/docker.sock`
- fix by running Docker Desktop/daemon and adding the user to the `docker` group, then restart the shell/session

Docker not running:
- common message: `Cannot connect to the Docker daemon`
- start Docker Desktop or the Docker service, then rerun tests

Image pull/network issues:
- common message mentions pulling `postgres:15-alpine`
- ensure Docker can reach the registry or pre-pull the image with `docker pull postgres:15-alpine`

WSL issues:
- ensure Docker Desktop has WSL integration enabled for the active distro
- if using native Docker inside WSL, check `sudo service docker status`
- restart Docker Desktop or the WSL distro if the socket is stale

Port conflicts should not usually happen because the helper maps Postgres to a random host port.

## How To Interpret DB Errors

Migration errors:
- failure during `New` usually means the schema SQL failed or the DSN points to an unreachable database

Uniqueness behavior:
- duplicate setup or record inserts should return `created=false`, not a database error

Missing-row behavior:
- missing record updates/deletes should return `false`
- missing password-update setup should return `applied=false`

Replay protection:
- password updates with `timestamp <= last_pwd_update_time` should return `applied=false`
- accepted updates should advance `last_pwd_update_time` and update the `cid_*` and `k_i_b64` fields together

## Verification

Expected command:

```bash
go test ./...
```

In environments without Docker access, the DB tests skip after reporting that test Postgres is unavailable. With Docker available, they run against the ephemeral Postgres container.
