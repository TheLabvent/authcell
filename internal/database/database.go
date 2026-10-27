// Package database is the PostgreSQL storage layer for AuthCell.
package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service is everything the HTTP layer needs from storage.
type Service interface {
	Ping(ctx context.Context) error
	Stats() map[string]any
	Close()

	CreateAPIKey(ctx context.Context, k NewAPIKey) (APIKey, error)
	GetAPIKeyByID(ctx context.Context, id string) (APIKey, error)
	GetAPIKeyByKeyID(ctx context.Context, keyID string) (APIKey, error)
	ListAPIKeys(ctx context.Context, f KeyFilter) ([]APIKey, int, error)
	UpdateAPIKey(ctx context.Context, id string, u APIKeyUpdate) (APIKey, error)
	RevokeAPIKey(ctx context.Context, id string) (APIKey, error)
	UpgradeKeyHash(ctx context.Context, id, hash string) error
	RecordUse(ctx context.Context, id string, window time.Duration) (UseResult, error)

	TrackUsage(ctx context.Context, apiKeyID, endpoint, ip string, status int) error
	ListUsage(ctx context.Context, apiKeyID string, before int64, limit int) ([]APIUsage, error)
	PruneUsage(ctx context.Context, olderThan time.Time) (int64, error)

	TrackAudit(ctx context.Context, actorType, actorID, eventType, ip string, data map[string]any) error
	ListAuditLog(ctx context.Context, f AuditFilter) ([]AuditLog, error)
}

// Options configures the connection pool.
type Options struct {
	MaxConns        int
	MinConns        int
	ConnMaxLifetime time.Duration
}

type service struct {
	pool *pgxpool.Pool
}

// Connect opens a pool, verifies connectivity and runs migrations.
func Connect(ctx context.Context, dsn string, opts Options) (Service, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = int32(opts.MaxConns)
	}
	if opts.MinConns > 0 && opts.MinConns <= int(cfg.MaxConns) {
		cfg.MinConns = int32(opts.MinConns)
	}
	if opts.ConnMaxLifetime > 0 {
		cfg.MaxConnLifetime = opts.ConnMaxLifetime
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}

	// Postgres often needs a few seconds to come up in compose; retry briefly.
	var pingErr error
	for attempt := 0; attempt < 10; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pingErr = pool.Ping(pingCtx)
		cancel()
		if pingErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	if pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", pingErr)
	}

	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &service{pool: pool}, nil
}

func (s *service) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *service) Close() { s.pool.Close() }

func (s *service) Stats() map[string]any {
	st := s.pool.Stat()
	return map[string]any{
		"total_conns":    st.TotalConns(),
		"idle_conns":     st.IdleConns(),
		"acquired_conns": st.AcquiredConns(),
		"max_conns":      st.MaxConns(),
	}
}

// mapErr turns driver errors into package sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrDuplicate
		case "22P02": // invalid_text_representation, e.g. a bad uuid
			return ErrNotFound
		}
	}
	return err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func jsonOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}

// validIP returns ip if it parses, else "", so bad input never breaks an insert.
func validIP(ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
