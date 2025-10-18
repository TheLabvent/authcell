package database

import "context"

func (s *service) CreateAPIKey(key APIKey) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO api_key
		 (id, key_hash, key_prefix, key_id, is_active, created_at, expires_at, rate_limit, usage_count)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		key.ID, key.KeyHash, key.KeyPrefix, key.KeyID, key.IsActive, key.CreatedAt, key.ExpiresAt, key.RateLimit, key.UsageCount)
	return err
}

func (s *service) GetAPIKeyByID(id string) (APIKey, error) {
	var key APIKey
	row := s.db.QueryRowContext(context.Background(),
		`SELECT id, key_hash, key_prefix, is_active, created_at, expires_at, rate_limit, usage_count
		 FROM api_key WHERE id=$1`, id)
	err := row.Scan(&key.ID, &key.KeyHash, &key.KeyPrefix, &key.IsActive,
		&key.CreatedAt, &key.ExpiresAt, &key.RateLimit, &key.UsageCount)
	return key, err
}

func (s *service) GetAPIKeyByPrefix(prefix string) (APIKey, error) {
	var key APIKey
	row := s.db.QueryRowContext(context.Background(),
		`SELECT id, key_hash, key_prefix, is_active, created_at, expires_at, rate_limit, usage_count
		 FROM api_key WHERE key_prefix=$1 LIMIT 1`, prefix)
	err := row.Scan(&key.ID, &key.KeyHash, &key.KeyPrefix, &key.IsActive,
		&key.CreatedAt, &key.ExpiresAt, &key.RateLimit, &key.UsageCount)
	return key, err
}

func (s *service) RevokeAPIKey(id string) error {
	_, err := s.db.ExecContext(context.Background(),
		`UPDATE api_key SET is_active=false WHERE id=$1`, id)
	return err
}

func (s *service) GetAPIKeyByKeyID(keyID string) (APIKey, error) {
	var key APIKey
	row := s.db.QueryRowContext(context.Background(),
		`SELECT id, key_id, key_hash, key_prefix, is_active, created_at, expires_at, rate_limit, usage_count
		 FROM api_key WHERE key_id=$1`, keyID)
	err := row.Scan(&key.ID, &key.KeyID, &key.KeyHash, &key.KeyPrefix, &key.IsActive,
		&key.CreatedAt, &key.ExpiresAt, &key.RateLimit, &key.UsageCount)
	return key, err
}
