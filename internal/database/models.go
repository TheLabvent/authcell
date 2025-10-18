package database

import (
	"encoding/json"
	"time"
)

type APIKey struct {
	ID         string
	KeyHash    string
	KeyPrefix  string
	IsActive   bool
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RateLimit  int
	UsageCount int
}

type APIUsage struct {
	ID       int64
	APIKeyID string
	Endpoint string
	UsedAt   time.Time
	Status   int
	RemoteIP string
}

type AuditLog struct {
	ID        int64           `json:"id"`
	ActorID   *string         `json:"actor_id"`
	ActorType string          `json:"actor_type"`
	EventType string          `json:"event_type"`
	EventData json.RawMessage `json:"event_data"`
	EventTime time.Time       `json:"event_time"`
	RemoteIP  string          `json:"remote_ip"`
}
