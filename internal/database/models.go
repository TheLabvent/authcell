package database

import (
	"encoding/json"
	"time"
)

type APIKey struct {
	ID         string     `json:"id"`
	KeyHash    string     `json:"key_hash"`
	KeyPrefix  string     `json:"key_prefix"`
	KeyID      string     `json:"key_id"`
	IsActive   bool       `json:"is_active"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RateLimit  int        `json:"rate_limit"`
	UsageCount int        `json:"usage_count"`
}

type APIUsage struct {
	ID       int64     `json:"id"`
	APIKeyID string    `json:"api_key_id"`
	Endpoint string    `json:"endpoint"`
	UsedAt   time.Time `json:"used_at"`
	Status   int       `json:"status"`
	RemoteIP string    `json:"remote_ip"`
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
