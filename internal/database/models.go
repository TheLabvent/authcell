package database

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrDuplicate is returned when a unique constraint is violated.
	ErrDuplicate = errors.New("duplicate")
)

// APIKey is a stored key. KeyHash is never serialized.
type APIKey struct {
	ID         string          `json:"id"`
	KeyID      string          `json:"key_id"`
	KeyHash    string          `json:"-"`
	KeyPrefix  string          `json:"key_prefix"`
	Name       string          `json:"name"`
	Metadata   json.RawMessage `json:"metadata"`
	IsActive   bool            `json:"is_active"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  *time.Time      `json:"expires_at"`
	RevokedAt  *time.Time      `json:"revoked_at"`
	LastUsedAt *time.Time      `json:"last_used_at"`
	RateLimit  int             `json:"rate_limit"`
	UsageCount int64           `json:"usage_count"`
}

// NewAPIKey holds the fields needed to insert a key.
type NewAPIKey struct {
	KeyID     string
	KeyHash   string
	KeyPrefix string
	Name      string
	Metadata  json.RawMessage
	ExpiresAt *time.Time
	RateLimit int
}

// APIKeyUpdate holds optional changes. Nil fields are left alone.
type APIKeyUpdate struct {
	Name         *string
	Metadata     json.RawMessage
	ExpiresAt    *time.Time
	ClearExpires bool
	RateLimit    *int
}

// KeyFilter narrows ListAPIKeys.
type KeyFilter struct {
	Active *bool
	Prefix string
	Limit  int
	Offset int
}

type APIUsage struct {
	ID       int64     `json:"id"`
	APIKeyID *string   `json:"api_key_id"`
	Endpoint string    `json:"endpoint"`
	UsedAt   time.Time `json:"used_at"`
	Status   int       `json:"status"`
	RemoteIP *string   `json:"remote_ip"`
}

type AuditLog struct {
	ID        int64           `json:"id"`
	ActorID   *string         `json:"actor_id"`
	ActorType string          `json:"actor_type"`
	EventType string          `json:"event_type"`
	EventData json.RawMessage `json:"event_data"`
	EventTime time.Time       `json:"event_time"`
	RemoteIP  *string         `json:"remote_ip"`
}

// AuditFilter narrows ListAuditLog. Before is an id cursor (exclusive).
type AuditFilter struct {
	EventType string
	Before    int64
	Limit     int
}

// UseResult is the outcome of recording a successful verification.
type UseResult struct {
	WindowCount int
	RateLimit   int
	WindowReset time.Time
}
