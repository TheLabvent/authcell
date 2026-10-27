package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrations run in order, once each, inside a transaction. Never edit a
// migration that has shipped; append a new one instead.
var migrations = []string{
	// 1: original schema. IF NOT EXISTS keeps it safe for databases created by
	// earlier AuthCell versions that had no migration table.
	`
	CREATE TABLE IF NOT EXISTS api_key (
		id uuid NOT NULL DEFAULT gen_random_uuid(),
		key_id text NOT NULL UNIQUE,
		key_hash text NOT NULL,
		key_prefix text NOT NULL,
		is_active boolean NULL DEFAULT true,
		created_at timestamptz NULL DEFAULT now(),
		expires_at timestamptz NULL,
		rate_limit integer NULL DEFAULT 1000,
		usage_count integer NULL DEFAULT 0,
		PRIMARY KEY (id)
	);
	CREATE TABLE IF NOT EXISTS api_usage (
		id bigserial NOT NULL,
		api_key_id uuid NULL,
		endpoint text NULL,
		used_at timestamptz NULL DEFAULT now(),
		status integer NULL,
		remote_ip inet NULL,
		PRIMARY KEY (id)
	);
	CREATE TABLE IF NOT EXISTS audit_log (
		id bigserial NOT NULL,
		actor_id uuid NULL,
		actor_type text NULL,
		event_type text NULL,
		event_data jsonb NULL,
		event_time timestamptz NULL DEFAULT now(),
		remote_ip inet NULL,
		PRIMARY KEY (id)
	);
	`,

	// 2: tighten nullability, add key metadata, rate-limit window, indexes.
	`
	UPDATE api_key SET is_active = COALESCE(is_active, true),
	                   created_at = COALESCE(created_at, now()),
	                   rate_limit = COALESCE(rate_limit, 0),
	                   usage_count = COALESCE(usage_count, 0);
	ALTER TABLE api_key
		ALTER COLUMN is_active SET NOT NULL,
		ALTER COLUMN created_at SET NOT NULL,
		ALTER COLUMN rate_limit SET NOT NULL,
		ALTER COLUMN rate_limit SET DEFAULT 0,
		ALTER COLUMN usage_count TYPE bigint,
		ALTER COLUMN usage_count SET NOT NULL,
		ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT '',
		ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
		ADD COLUMN IF NOT EXISTS revoked_at timestamptz NULL,
		ADD COLUMN IF NOT EXISTS last_used_at timestamptz NULL,
		ADD COLUMN IF NOT EXISTS window_start timestamptz NULL,
		ADD COLUMN IF NOT EXISTS window_count integer NOT NULL DEFAULT 0;
	ALTER TABLE api_key ADD CONSTRAINT api_key_rate_limit_nonneg CHECK (rate_limit >= 0);
	-- key_id already has a UNIQUE index; the extra one was redundant.
	DROP INDEX IF EXISTS idx_key_id;
	CREATE INDEX IF NOT EXISTS idx_api_key_created_at ON api_key (created_at DESC);

	UPDATE api_usage SET used_at = COALESCE(used_at, now());
	ALTER TABLE api_usage ALTER COLUMN used_at SET NOT NULL;
	CREATE INDEX IF NOT EXISTS idx_api_usage_key_id ON api_usage (api_key_id, id DESC);
	CREATE INDEX IF NOT EXISTS idx_api_usage_used_at ON api_usage (used_at);

	-- actor_id used to be a random uuid per event, which carried no meaning.
	ALTER TABLE audit_log ALTER COLUMN actor_id TYPE text USING actor_id::text;
	UPDATE audit_log SET event_time = COALESCE(event_time, now());
	ALTER TABLE audit_log ALTER COLUMN event_time SET NOT NULL;
	CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log (event_type, id DESC);
	`,
}

// lockID is an arbitrary constant so concurrent instances don't race on migrations.
const lockID = 7_446_563_311

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	var current int
	if err := conn.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}

	for i := current; i < len(migrations); i++ {
		version := i + 1
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, migrations[i]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %d: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
