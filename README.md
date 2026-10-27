# AuthCell

> Self-hosted API key management as a standalone microservice.

AuthCell issues, verifies, rate-limits, rotates and revokes API keys for your own services. It is a single Go binary backed by PostgreSQL, with no external services and no telemetry.

## Features

- Full key lifecycle: create, list, inspect, update, rotate, revoke
- Fast verification: one indexed lookup plus a constant-time SHA-256 compare
- Per-key rate limits that hold across multiple AuthCell instances
- Expiry, names and JSON metadata on every key
- Usage log for every verification and an audit log for every admin action
- Admin API protected by a bearer token, optional token for the verify endpoint
- Versioned, lock-protected schema migrations that run on startup
- Distroless Docker image, Docker Compose setup, zero-dependency Node and Python clients

---

## Quick start

```bash
cp .env.example .env
# Set a real admin token and DB password in .env:
#   AUTHCELL_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose up --build
```

Then:

```bash
export TOKEN=<your AUTHCELL_ADMIN_TOKEN>

# Create a key (the plaintext key is returned only once)
curl -s -X POST http://localhost:8080/v1/keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_prefix":"live","name":"billing-service","rate_limit":1000}'

# Verify it (this is what your services call on each request)
curl -s -X POST http://localhost:8080/v1/keys/verify \
  -H "Content-Type: application/json" \
  -d '{"api_key":"live_3f9c2a71d04be855_..."}'
```

To run without Docker, start Postgres, fill in `.env`, and run `make run`.

---

## Key format

```
live_3f9c2a71d04be855_9b1f0c2e7d4a...  (48 hex chars)
└┬─┘ └──────┬───────┘ └──────┬──────┘
prefix    key_id           secret
```

- **prefix**: optional. Letters, digits and single underscores, up to 32 characters (`live`, `test`, `my_app`). A trailing underscore is ignored, so `demo_` and `demo` are the same.
- **key_id**: 16 hex characters (64 bits). Indexed, so lookups never scan.
- **secret**: 48 hex characters (192 bits) from `crypto/rand`.

Only a SHA-256 digest of the full key is stored. Because the key is long and random, a fast hash is safe here (this is the same approach GitHub and Stripe use for tokens), and it avoids bcrypt's CPU cost on every request. Keys created by older versions with bcrypt still verify, and are moved to the new format the first time they are used.

---

## Authentication

| Endpoint | Auth |
| --- | --- |
| `GET /v1/health` | none |
| `POST /v1/keys/verify` | none, or `AUTHCELL_VERIFY_TOKEN` when set (the admin token also works) |
| everything else | `Authorization: Bearer <AUTHCELL_ADMIN_TOKEN>` |

AuthCell refuses to start without an admin token of at least 32 characters. Keep it on your backend; never ship it to browsers or mobile apps.

---

## API

All responses share one envelope:

```json
{ "status": "success", "code": 200, "data": { ... }, "meta": { ... }, "timestamp": 1730000000 }
{ "status": "error", "code": 400, "message": "rate_limit cannot be negative", "timestamp": 1730000000 }
```

Full Postman collection: [AuthCell on Postman](https://documenter.getpostman.com/view/28328727/2sB3QQJnT4#be11f7c6-14f0-4a50-9d05-a726046306fa)

### Keys

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/keys` | Create a key |
| `GET` | `/v1/keys` | List keys. Query: `limit` (max 500), `offset`, `active=true\|false`, `prefix` |
| `GET` | `/v1/keys/:id` | Get one key by its UUID |
| `PATCH` | `/v1/keys/:id` | Update `name`, `metadata`, `expires_at` (`null` removes it), `rate_limit` |
| `DELETE` | `/v1/keys/:id` | Revoke a key (idempotent) |
| `POST` | `/v1/keys/:id/rotate` | Issue a new key with the same settings and revoke the old one |
| `POST` | `/v1/keys/verify` | Verify a key |

**Create** body (all fields optional):

```json
{
  "key_prefix": "live",
  "name": "billing-service",
  "metadata": { "team": "payments", "plan": "pro" },
  "expires_at": "2027-01-01T00:00:00Z",
  "rate_limit": 1000
}
```

`rate_limit` is the number of successful verifications allowed per `RATE_LIMIT_WINDOW` (default one minute). `0` means unlimited, and is the default.

Create and rotate return the key record plus `api_key`, the plaintext key. It is not stored and cannot be shown again.

**Verify** takes `{"api_key": "..."}` or an `X-API-Key` header.

| Status | `data` |
| --- | --- |
| `200` | `{"valid": true, "id", "key_id", "key_prefix", "name", "metadata", "expires_at", "rate_limit": {"limit", "remaining", "reset"} \| null}` |
| `401` | `{"valid": false, "reason": "invalid" \| "revoked" \| "expired"}` |
| `429` | `{"valid": false, "reason": "rate_limited"}` plus a `Retry-After` header |
| `400` | missing `api_key` |

`reason` is only more specific than `invalid` once the caller has proven they hold the real key, so verify never reveals which keys exist. Rate-limited keys also get `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers.

### Usage and audit

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/usage/:id` | Verification attempts for a key, newest first |
| `GET` | `/v1/audit` | Admin events (`create_key`, `update_key`, `revoke_key`, `rotate_key`). Filter with `event_type` |

Both take `limit` and `before`. To page, pass `meta.next_before` from the previous response as `before`.

Usage rows older than `USAGE_RETENTION_DAYS` (default 90) are deleted hourly.

### Health

`GET /v1/health` returns `200` with pool stats when the database answers and `503` when it doesn't. The binary also has a built-in probe (`authcell -healthcheck`) that the Docker image uses.

---

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `AUTHCELL_ADMIN_TOKEN` | required | Bearer token for management endpoints, 32+ chars |
| `AUTHCELL_VERIFY_TOKEN` | empty | If set, required for `/v1/keys/verify` |
| `PORT` | `8080` | HTTP port |
| `APP_ENV` | `production` | Shown in logs |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | empty | Full Postgres URL. Overrides the `DB_*` values |
| `DB_HOST` / `DB_PORT` | `localhost` / `5432` | |
| `DB_DATABASE` | `postgres` | |
| `DB_USERNAME` / `DB_PASSWORD` | `postgres` / empty | Special characters are escaped for you |
| `DB_SCHEMA` | `public` | |
| `DB_SSLMODE` | `disable` | Use `require` or `verify-full` for remote databases |
| `DB_MAX_CONNS` / `DB_MIN_CONNS` | `25` / `2` | Connection pool size |
| `RATE_LIMIT_WINDOW` | `1m` | Window for per-key `rate_limit` |
| `USAGE_RETENTION_DAYS` | `90` | `0` keeps usage rows forever |
| `REQUEST_TIMEOUT` | `10s` | Per-request database timeout |
| `CORS_ORIGINS` | empty | Comma-separated origins. Empty disables CORS |
| `TRUSTED_PROXIES` | empty | Proxy IPs/CIDRs whose `X-Forwarded-For` is trusted for client IPs |

---

## Client libraries

Both clients read `AUTHCELL_URL` (default `http://localhost:8080/v1`), `AUTHCELL_ADMIN_TOKEN` and `AUTHCELL_VERIFY_TOKEN` from the environment, or take them as arguments. `verifyKey` / `verify_key` never throws for a bad key; check `.valid`. Other calls throw `AuthCellError` with `status` and `message`.

### Node.js / TypeScript

`client/nodejs`, Node 18+, no runtime dependencies. Build with `npm install && npm run build`.

```typescript
import { AuthCellClient } from "./client/nodejs/dist/index.js";

const authcell = new AuthCellClient(); // or new AuthCellClient({ baseUrl, adminToken })

const key = await authcell.createKey({ key_prefix: "live", name: "billing", rate_limit: 1000 });
console.log("Give this to the customer once:", key.api_key);

const result = await authcell.verifyKey(key.api_key);
if (!result.valid) console.log("rejected:", result.reason);

await authcell.rotateKey(key.id);
```

### Python

`client/python/authcell.py`, Python 3.8+, standard library only.

```python
from client.python.authcell import AuthCellClient

authcell = AuthCellClient()  # or AuthCellClient(base_url=..., admin_token=...)

key = authcell.create_key(key_prefix="live", name="billing", rate_limit=1000)
print("Give this to the customer once:", key.api_key)

result = authcell.verify_key(key.api_key)
if not result.valid:
    print("rejected:", result.reason)

authcell.revoke_key(key.id)
```

---

## Development

```bash
make run      # run locally (reads .env)
make watch    # live reload with air
make test     # unit tests; integration tests skip without a database
make itest    # unit + integration tests against Postgres (TEST_DB=postgres://...)
make lint     # gofmt + go vet
make build    # ./main with version baked in
```

Integration tests create and drop their own schema, so they are safe to point at a shared dev database. CI runs them against a Postgres service container.

Releases are built by GoReleaser when a `v*.*.*` tag is pushed.

---

## Upgrading from earlier versions

Start the new version against your existing database. Migrations run automatically and:

- add `name`, `metadata`, `revoked_at`, `last_used_at` and rate-limit window columns to `api_key`
- make `is_active`, `created_at`, `rate_limit` and `usage_count` non-null (existing nulls are filled)
- change `audit_log.actor_id` from `uuid` to `text`
- add indexes for usage and audit lookups

Behaviour changes to know about:

- All management endpoints now need the admin token. Update your clients.
- `rate_limit` is now enforced. Existing keys keep their stored value; set it to `0` with `PATCH` for unlimited.
- Old `demo_xxxxxxxx_<uuid>` keys keep working and are rehashed on first use. Keys created by the old version with a prefix longer than 27 characters were stored with an empty hash due to bcrypt's 72-byte limit and never worked. Rotate or recreate those.
- `key_hash` is no longer returned by any endpoint.

---

AuthCell does one thing: secure key verification for your own APIs. There are no dashboards, billing or tenants, by design.
