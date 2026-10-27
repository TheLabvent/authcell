package database

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const keyColumns = `id::text, key_id, key_hash, key_prefix, name, metadata, is_active,
	created_at, expires_at, revoked_at, last_used_at, rate_limit, usage_count`

func scanKey(row pgx.Row) (APIKey, error) {
	var k APIKey
	var meta []byte
	err := row.Scan(&k.ID, &k.KeyID, &k.KeyHash, &k.KeyPrefix, &k.Name, &meta, &k.IsActive,
		&k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.RateLimit, &k.UsageCount)
	if err != nil {
		return APIKey{}, mapErr(err)
	}
	k.Metadata = meta
	return k, nil
}

func (s *service) CreateAPIKey(ctx context.Context, n NewAPIKey) (APIKey, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO api_key (key_id, key_hash, key_prefix, name, metadata, expires_at, rate_limit)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+keyColumns,
		n.KeyID, n.KeyHash, n.KeyPrefix, n.Name, jsonOrEmpty(n.Metadata), n.ExpiresAt, n.RateLimit)
	return scanKey(row)
}

func (s *service) GetAPIKeyByID(ctx context.Context, id string) (APIKey, error) {
	return scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM api_key WHERE id = $1`, id))
}

func (s *service) GetAPIKeyByKeyID(ctx context.Context, keyID string) (APIKey, error) {
	return scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM api_key WHERE key_id = $1`, keyID))
}

func (s *service) ListAPIKeys(ctx context.Context, f KeyFilter) ([]APIKey, int, error) {
	var where []string
	var args []any
	if f.Active != nil {
		args = append(args, *f.Active)
		where = append(where, "is_active = $1")
	}
	if f.Prefix != "" {
		args = append(args, strings.TrimRight(f.Prefix, "_"))
		where = append(where, "rtrim(key_prefix, '_') = $"+strconv.Itoa(len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM api_key`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, `SELECT `+keyColumns+` FROM api_key`+clause+
		` ORDER BY created_at DESC, id LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]APIKey, 0, f.Limit)
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, k)
	}
	return out, total, rows.Err()
}

func (s *service) UpdateAPIKey(ctx context.Context, id string, u APIKeyUpdate) (APIKey, error) {
	var meta any
	if len(u.Metadata) > 0 {
		meta = []byte(u.Metadata)
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE api_key SET
			name       = COALESCE($2, name),
			metadata   = COALESCE($3::jsonb, metadata),
			expires_at = CASE WHEN $4 THEN NULL ELSE COALESCE($5, expires_at) END,
			rate_limit = COALESCE($6, rate_limit)
		WHERE id = $1
		RETURNING `+keyColumns,
		id, u.Name, meta, u.ClearExpires, u.ExpiresAt, u.RateLimit)
	return scanKey(row)
}

// RevokeAPIKey deactivates a key. Revoking an already revoked key is a no-op
// that still returns the key, so the call is idempotent.
func (s *service) RevokeAPIKey(ctx context.Context, id string) (APIKey, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE api_key SET is_active = false, revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1
		RETURNING `+keyColumns, id)
	return scanKey(row)
}

func (s *service) UpgradeKeyHash(ctx context.Context, id, hash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_key SET key_hash = $2 WHERE id = $1`, id, hash)
	return err
}

// RecordUse bumps usage counters and the fixed rate-limit window in one atomic
// statement, so limits hold across multiple AuthCell instances.
func (s *service) RecordUse(ctx context.Context, id string, window time.Duration) (UseResult, error) {
	var r UseResult
	var start time.Time
	err := s.pool.QueryRow(ctx, `
		UPDATE api_key SET
			usage_count  = usage_count + 1,
			last_used_at = now(),
			window_count = CASE WHEN window_start IS NOT NULL AND window_start > now() - $2::interval
			                    THEN window_count + 1 ELSE 1 END,
			window_start = CASE WHEN window_start IS NOT NULL AND window_start > now() - $2::interval
			                    THEN window_start ELSE now() END
		WHERE id = $1
		RETURNING window_count, rate_limit, window_start`,
		id, window).Scan(&r.WindowCount, &r.RateLimit, &start)
	if err != nil {
		return UseResult{}, mapErr(err)
	}
	r.WindowReset = start.Add(window)
	return r, nil
}
