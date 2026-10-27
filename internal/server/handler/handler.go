// Package handler contains the HTTP handlers for AuthCell.
package handler

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"authcell/internal/database"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	defaultPageSize = 50
	maxPageSize     = 500

	actorAdmin = "admin"
	actorAPI   = "api"
)

// Handler holds dependencies shared by all endpoints.
type Handler struct {
	DB              database.Service
	RateLimitWindow time.Duration
	RequestTimeout  time.Duration
	Version         string
}

func New(db database.Service, rateWindow, requestTimeout time.Duration, version string) *Handler {
	if rateWindow <= 0 {
		rateWindow = time.Minute
	}
	if requestTimeout <= 0 {
		requestTimeout = 10 * time.Second
	}
	return &Handler{DB: db, RateLimitWindow: rateWindow, RequestTimeout: requestTimeout, Version: version}
}

// ctx returns a request-scoped context with the configured timeout.
func (h *Handler) ctx(c *fiber.Ctx) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.UserContext(), h.RequestTimeout)
}

// audit records an event without failing the request if logging fails.
func (h *Handler) audit(ctx context.Context, c *fiber.Ctx, actorType, actorID, event string, data map[string]any) {
	if err := h.DB.TrackAudit(ctx, actorType, actorID, event, c.IP(), data); err != nil {
		slog.Warn("audit write failed", "event", event, "error", err)
	}
}

func (h *Handler) usage(ctx context.Context, c *fiber.Ctx, apiKeyID string, status int) {
	if err := h.DB.TrackUsage(ctx, apiKeyID, c.Path(), c.IP(), status); err != nil {
		slog.Warn("usage write failed", "error", err)
	}
}

func validUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

func pageSize(c *fiber.Ctx) (int, bool) {
	raw := c.Query("limit")
	if raw == "" {
		return defaultPageSize, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, false
	}
	if n > maxPageSize {
		n = maxPageSize
	}
	return n, true
}

func nonNegInt64(c *fiber.Ctx, name string) (int64, bool) {
	raw := c.Query(name)
	if raw == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
