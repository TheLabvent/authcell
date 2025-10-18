# AuthCell

> Self-hosted API key management as a standalone microservice.

**No vendor lock-in. No external dependencies. Secure and fast.**

**AuthCell** is a self‑contained, open‑source API key management and verification service.
It provides a fast, lightweight, and self‑hosted alternative to commercial key management solutions, enabling developers to generate, verify, audit, and revoke API keys securely within their own environment.

---

## Overview

AuthCell offers a drop‑in API security layer that can integrate into any stack or existing microservice.
Designed for simplicity, privacy, and host control, AuthCell runs as a single containerized service — with no external dependencies other than PostgreSQL.

## Features

- Full API key lifecycle (create, verify, revoke)
- Detailed usage tracking and audit logging
- bcrypt‑based key hashing
- Docker Compose deployment
- Zero cloud lock‑in or external dependencies

---

## API Endpoints

### Health

```
GET /v1/health
→ Returns database and service health.
```

### API Key Management

| Method | Path              | Description                       |
| ------ | ----------------- | --------------------------------- |
| POST   | `/v1/keys`        | Create a new API key              |
| GET    | `/v1/keys/:id`    | Retrieve key metadata by UUID     |
| POST   | `/v1/keys/verify` | Verify validity of a provided key |
| DELETE | `/v1/keys/:id`    | Revoke an API key                 |

### Usage and Audit

| Method | Path            | Description                                   |
| ------ | --------------- | --------------------------------------------- |
| GET    | `/v1/usage/:id` | Retrieve usage logs for a specific key        |
| GET    | `/v1/audit`     | Retrieve a chronological list of audit events |

---

## Security Details

### 1. Key Hashing (bcrypt)

All API keys are irreversibly hashed with **bcrypt** before being stored.
This ensures that raw keys are **never persisted** in the database and cannot be recovered — only verified.

### 2. Unique Key ID for O(1) Validation

Each key includes a unique 8‑character `key_id` (randomized via crypto/rand).
Verification queries directly by `key_id`, resulting in:

- Constant‑time lookups
- No prefix collisions
- No multi‑row scans

**Example key format:**

```
demo_4d83e91f_98d9c77a-b067-4723-9325-70f59dfd448b
```

Where:

- `demo_` → Environment or custom prefix
- `4d83e91f` → Unique indexed `key_id`
- `98d9c77a…` → UUID for entropy

### 3. Database Protection

The `api_key` table defines:

- `key_hash` (secured via bcrypt)
- `key_prefix` and `key_id` (metadata only)
- `UNIQUE INDEX` on `key_id` for deterministic queries
- `is_active`, `expires_at`, and `rate_limit` fields for policy enforcement

### 4. Audit and Usage Logging

Every key event — creation, verification, or revocation — is recorded in:

- `audit_log` table (action, IP, event data, timestamp)
- `api_usage` table (key ID, endpoint, HTTP status, remote IP)

This provides complete traceability for compliance and debugging.

---

AuthCell is intentionally simpler than enterprise products — no dashboards, billing logic, or tenant management.
Its single goal is **secure key verification**, optimized for embedded or internal API use cases.

---

## Deployment

### Using Docker Compose

```bash
docker compose up --build
```

On first startup, AuthCell:

1. Connects to PostgreSQL
2. Automatically migrates all necessary tables
3. Starts the REST server on port `8080`

---

## Environment Variables

| Variable      | Description       | Default     |
| ------------- | ----------------- | ----------- |
| `DB_HOST`     | Database hostname | `localhost` |
| `DB_PORT`     | Database port     | `5432`      |
| `DB_USERNAME` | Database user     | —           |
| `DB_PASSWORD` | Database password | —           |
| `DB_DATABASE` | Database name     | `postgres`  |
| `DB_SCHEMA`   | Database schema   | `public`    |
| `PORT`        | Web server port   | `8080`      |

---

## Example Usage

**Create a new API key**

```bash
curl -X POST http://localhost:8080/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"key_prefix":"demo_","rate_limit":1000}'
```

**Verify**

```bash
curl -X POST http://localhost:8080/v1/keys/verify \
  -H "Content-Type: application/json" \
  -d '{"api_key":"demo_4d83e91f_98d9c77a-b067-4723-9325-70f59dfd448b"}'
```

---

### TL;DR

AuthCell is a **self‑hosted, developer‑first** API key service —
no external dependencies, no telemetry, no hidden databases.
It’s small enough to embed directly into your own product yet secure enough to protect live production APIs.
