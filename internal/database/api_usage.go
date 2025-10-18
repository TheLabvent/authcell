package database

import "context"

func (s *service) TrackUsage(keyID, endpoint, ip string, status int) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO api_usage (api_key_id, endpoint, remote_ip, status)
		 VALUES ($1, $2, $3, $4)`, keyID, endpoint, ip, status)
	return err
}

func (s *service) ListUsage(keyID string) ([]APIUsage, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, api_key_id, endpoint, used_at, status, remote_ip
		 FROM api_usage WHERE api_key_id=$1 ORDER BY used_at DESC LIMIT 100`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usages []APIUsage
	for rows.Next() {
		var u APIUsage
		if err := rows.Scan(&u.ID, &u.APIKeyID, &u.Endpoint, &u.UsedAt, &u.Status, &u.RemoteIP); err == nil {
			usages = append(usages, u)
		}
	}
	return usages, nil
}
