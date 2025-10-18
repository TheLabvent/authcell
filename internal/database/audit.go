package database

import (
	"context"
	"encoding/json"
	"fmt"
)

func (s *service) TrackAudit(actorType, eventType, ip string, data map[string]any) error {
	payload, _ := json.Marshal(data)
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO audit_log (actor_id, actor_type, event_type, event_data, remote_ip)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4)`,
		actorType, eventType, payload, ip)
	return err
}

func (s *service) ListAuditLog() ([]AuditLog, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, actor_id, actor_type, event_type, event_data, event_time, remote_ip
		 FROM audit_log ORDER BY event_time DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.ActorID, &l.ActorType, &l.EventType, &l.EventData, &l.EventTime, &l.RemoteIP); err != nil {
			fmt.Printf("Audit scan error: %v\n", err)
			continue
		}
		logs = append(logs, l)
	}
	return logs, nil
}
