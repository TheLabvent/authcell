package handler

import (
	"context"
	"strings"
	"time"

	"authcell/internal/database"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
)

// ListAPIUsage handles GET /v1/usage/:id?limit=&before=.
func (h *Handler) ListAPIUsage(c *fiber.Ctx) error {
	id := c.Params("id")
	if !validUUID(id) {
		return response.Error(c, fiber.StatusBadRequest, "id must be a UUID")
	}
	limit, ok := pageSize(c)
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "limit must be a positive integer")
	}
	before, ok := nonNegInt64(c, "before")
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "before must be a non-negative integer")
	}

	ctx, cancel := h.ctx(c)
	defer cancel()
	rows, err := h.DB.ListUsage(ctx, id, before, limit)
	if err != nil {
		return response.Internal(c, "Failed to fetch usage", err)
	}
	return response.List(c, rows, cursorMeta(len(rows), limit, func() int64 { return rows[len(rows)-1].ID }))
}

// ListAuditLog handles GET /v1/audit?limit=&before=&event_type=.
func (h *Handler) ListAuditLog(c *fiber.Ctx) error {
	limit, ok := pageSize(c)
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "limit must be a positive integer")
	}
	before, ok := nonNegInt64(c, "before")
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "before must be a non-negative integer")
	}

	ctx, cancel := h.ctx(c)
	defer cancel()
	rows, err := h.DB.ListAuditLog(ctx, database.AuditFilter{
		EventType: strings.TrimSpace(c.Query("event_type")), Before: before, Limit: limit,
	})
	if err != nil {
		return response.Internal(c, "Failed to fetch audit log", err)
	}
	return response.List(c, rows, cursorMeta(len(rows), limit, func() int64 { return rows[len(rows)-1].ID }))
}

// cursorMeta returns next_before only when a full page came back.
func cursorMeta(n, limit int, lastID func() int64) fiber.Map {
	meta := fiber.Map{"limit": limit, "next_before": nil}
	if n == limit && n > 0 {
		meta["next_before"] = lastID()
	}
	return meta
}

// Health handles GET /v1/health. It returns 503 when the database is down
// instead of crashing the process.
func (h *Handler) Health(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
	defer cancel()
	if err := h.DB.Ping(ctx); err != nil {
		return response.ErrorWithData(c, fiber.StatusServiceUnavailable, "Database unreachable",
			fiber.Map{"status": "down", "version": h.Version})
	}
	return response.Success(c, fiber.StatusOK, fiber.Map{
		"status": "up", "version": h.Version, "database": h.DB.Stats(),
	})
}
