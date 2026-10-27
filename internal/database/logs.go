package database

import (
	"context"
	"encoding/json"
	"time"
)

// TrackUsage records one verification attempt. apiKeyID and ip may be empty.
func (s *service) TrackUsage(ctx context.Context, apiKeyID, endpoint, ip string, status int) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO api_usage (api_key_id, endpoint, remote_ip, status)
		VALUES ($1::uuid, $2, $3::inet, $4)`,
		nullable(apiKeyID), endpoint, nullable(validIP(ip)), status)
	return err
}

func (s *service) ListUsage(ctx context.Context, apiKeyID string, before int64, limit int) ([]APIUsage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, api_key_id::text, COALESCE(endpoint, ''), used_at, COALESCE(status, 0), host(remote_ip)
		FROM api_usage
		WHERE api_key_id = $1 AND ($2 = 0 OR id < $2)
		ORDER BY id DESC LIMIT $3`, apiKeyID, before, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make([]APIUsage, 0, limit)
	for rows.Next() {
		var u APIUsage
		if err := rows.Scan(&u.ID, &u.APIKeyID, &u.Endpoint, &u.UsedAt, &u.Status, &u.RemoteIP); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *service) PruneUsage(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_usage WHERE used_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *service) TrackAudit(ctx context.Context, actorType, actorID, eventType, ip string, data map[string]any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, event_type, event_data, remote_ip)
		VALUES ($1, $2, $3, $4, $5::inet)`,
		actorType, nullable(actorID), eventType, payload, nullable(validIP(ip)))
	return err
}

func (s *service) ListAuditLog(ctx context.Context, f AuditFilter) ([]AuditLog, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, actor_id, COALESCE(actor_type, ''), COALESCE(event_type, ''),
		       COALESCE(event_data, '{}'::jsonb), event_time, host(remote_ip)
		FROM audit_log
		WHERE ($1 = '' OR event_type = $1) AND ($2 = 0 OR id < $2)
		ORDER BY id DESC LIMIT $3`, f.EventType, f.Before, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AuditLog, 0, f.Limit)
	for rows.Next() {
		var l AuditLog
		var data []byte
		if err := rows.Scan(&l.ID, &l.ActorID, &l.ActorType, &l.EventType, &data, &l.EventTime, &l.RemoteIP); err != nil {
			return nil, err
		}
		l.EventData = data
		out = append(out, l)
	}
	return out, rows.Err()
}
