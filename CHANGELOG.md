# Changelog

All notable changes to AuthCell are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-28

A security and reliability release. The admin API is now authenticated, key
hashing is faster and no longer drops long keys, and rate limits are enforced.
**This release has breaking changes.** See "Upgrading" below.

### Security

- All management endpoints now require `Authorization: Bearer <AUTHCELL_ADMIN_TOKEN>`.
  Before this, anyone who could reach the port could create, list and revoke keys.
- `GET /v1/keys/:id` no longer returns `key_hash`. No endpoint does.
- Error responses no longer include raw database errors. Details are logged server side.
- Verify returns a generic `invalid` reason until the caller proves they hold the real
  key, so it can't be used to find out which key ids exist.
- CORS is off by default. Set `CORS_ORIGINS` to allow browser access.
- The Docker image no longer copies `.env` into the build context, runs as non-root on
  distroless, and Postgres is only published on `127.0.0.1` in Compose.
- The server refuses to start with a missing, short (< 32 chars) or placeholder admin token.

### Added

- `GET /v1/keys` with `limit`, `offset`, `active` and `prefix` filters.
- `PATCH /v1/keys/:id` to change `name`, `metadata`, `expires_at` (send `null` to clear) and `rate_limit`.
- `POST /v1/keys/:id/rotate` issues a replacement key with the same settings and revokes the old one.
- `name` and JSON `metadata` on keys.
- Per-key rate limiting over `RATE_LIMIT_WINDOW` (default `1m`), safe across multiple
  instances. Responses include `X-RateLimit-*` headers, and `429` responses include `Retry-After`.
- Verify accepts the key in an `X-API-Key` header as well as the JSON body, and returns
  the key's id, prefix, name, metadata, expiry and remaining rate limit.
- Optional `AUTHCELL_VERIFY_TOKEN` to protect the verify endpoint.
- `last_used_at`, `revoked_at` and a real `usage_count`.
- Cursor pagination (`limit`, `before`, `meta.next_before`) for usage and audit logs, and
  an `event_type` filter for audit.
- Hourly pruning of usage rows older than `USAGE_RETENTION_DAYS` (default 90).
- Versioned schema migrations guarded by a Postgres advisory lock.
- `DATABASE_URL`, `DB_SSLMODE`, `DB_MAX_CONNS`, `DB_MIN_CONNS`, `REQUEST_TIMEOUT`,
  `TRUSTED_PROXIES` and `LOG_LEVEL` settings.
- Structured JSON request logs with request ids.
- `authcell -version` and `authcell -healthcheck` (used by the Docker `HEALTHCHECK`).
- Node client: `listKeys`, `updateKey`, `rotateKey`, `health`, `AuthCellError`, timeouts,
  plus `package.json` and `tsconfig.json` so it builds as a package.
- Python client: `list_keys`, `update_key`, `rotate_key`, `health`, `AuthCellError`.
- Unit tests, plus integration tests that run against a real Postgres when
  `AUTHCELL_TEST_DATABASE_URL` is set. CI runs both.
- `make lint` and `make itest`.

### Changed

- New key format: `<prefix>_<16 hex key_id>_<48 hex secret>`. The prefix is optional and
  may contain single underscores. A trailing underscore on input is ignored.
- Keys are stored as SHA-256 digests instead of bcrypt, which removes about 80 ms of CPU
  from every verify. Old bcrypt keys still verify and are rehashed on first use.
- Verify failures return `data: {"valid": false, "reason": ...}` with `401` (`invalid`,
  `revoked`, `expired`) or `429` (`rate_limited`).
- Revoke returns the revoked key, and is idempotent.
- `rate_limit` defaults to `0` (unlimited) and must be non-negative.
- `audit_log.actor_id` is now `text`. It used to hold a random UUID per event.
- Clients read `AUTHCELL_ADMIN_TOKEN` and `AUTHCELL_VERIFY_TOKEN` from the environment.
  `verifyKey` / `verify_key` return a result instead of throwing for a bad key.
- `PORT` defaults to `8080` instead of silently binding a random port when unset.
- Go 1.24. Dockerfile, CI and `go.mod` now agree on the version.
- Compose always points the app at the `postgres` service, whatever `DB_HOST` says in `.env`.
- Postgres image pinned to `17-alpine` instead of `latest`.

### Fixed

- Keys with a prefix longer than 27 characters were saved with an empty hash (bcrypt's
  72-byte limit, error ignored) and could never be verified.
- Prefixes without a trailing underscore, prefixes containing underscores, and empty
  prefixes produced keys that could never be verified.
- `/v1/health` called `log.Fatalf` when the database was down, killing the server. It now returns `503`.
- Key listing queried a table that doesn't exist (`api_keys`) and wasn't routed.
- Revoking an unknown id returned `200`. It now returns `404`, and a malformed id returns `400`.
- Usage rows for unknown keys failed to insert (empty string into a `uuid` column).
- Rows with `NULL` columns were silently dropped from usage and audit listings.
- Empty listings returned `null` instead of `[]`.
- Both clients threw on every revoke because the response had no `data` field.
- 8-character key ids (32 bits) caused unique-constraint failures as key counts grew. Ids
  are now 64 bits, with a retry on collision.
- Database passwords with special characters broke the connection string.
- The database pool was never closed on shutdown.
- The route table was printed to stdout on every start.
- Release workflow passed the git tag as the GoReleaser version to install.
- GoReleaser injected the version into a placeholder package path that didn't exist.
- CI used Go 1.22 while `go.mod` required 1.25.3.

### Removed

- `testcontainers-go`. Integration tests use any Postgres you point them at.
- The unused `GetAPIKeyByPrefix` query.

### Upgrading from 0.0.x

1. Generate an admin token: `openssl rand -hex 32`, and set it as `AUTHCELL_ADMIN_TOKEN`.
2. Send `Authorization: Bearer <token>` on every call except `/v1/health` and `/v1/keys/verify`.
3. Start 0.1.0 against your existing database. Migrations run automatically.
4. Check `rate_limit` on existing keys. It is now enforced per `RATE_LIMIT_WINDOW`. Set it
   to `0` with `PATCH /v1/keys/:id` for unlimited.
5. Recreate or rotate any key whose prefix is longer than 27 characters. Those never worked.
6. If your code checked for `401` from verify, it still works. If it parsed `message`,
   switch to `data.reason`.

## [0.0.2] - 2025-10-23

- Added the API key listing handler.
- Updated the Node and Python clients.

## [0.0.1] - 2025-10-19

Initial release: create, get, verify and revoke keys, usage and audit logs,
Node and Python clients.

[0.1.0]: https://github.com/TheLabvent/authcell/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/TheLabvent/authcell/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/TheLabvent/authcell/releases/tag/v0.0.1
