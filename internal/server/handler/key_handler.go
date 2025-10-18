package handler

import (
	"authcell/internal/app"
	"authcell/internal/database"
	"authcell/internal/server/response"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func CreateAPIKey(server *app.FiberServer, ctx *fiber.Ctx) error {
	var req struct {
		KeyPrefix string     `json:"key_prefix"`
		ExpiresAt *time.Time `json:"expires_at"`
		RateLimit int        `json:"rate_limit"`
	}

	if err := ctx.BodyParser(&req); err != nil {
		return response.Error(ctx, 400, "Invalid request body", err)
	}

	fullKey := fmt.Sprintf("%s%s", req.KeyPrefix, uuid.New().String())
	hashed, _ := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)

	apiKey := database.APIKey{
		ID:         uuid.New().String(),
		KeyHash:    string(hashed),
		KeyPrefix:  req.KeyPrefix,
		IsActive:   true,
		CreatedAt:  time.Now(),
		ExpiresAt:  req.ExpiresAt,
		RateLimit:  req.RateLimit,
		UsageCount: 0,
	}
	if err := server.Db.CreateAPIKey(apiKey); err != nil {
		return response.Error(ctx, 500, "Failed to create API key", err)
	}

	// Audit log
	server.Db.TrackAudit("system", "create_key", ctx.IP(), map[string]any{
		"key_id": apiKey.ID,
		"prefix": apiKey.KeyPrefix,
	})

	return response.Success(ctx, 201, fiber.Map{
		"api_key": fullKey,
		"id":      apiKey.ID,
	})
}

func GetAPIKey(server *app.FiberServer, ctx *fiber.Ctx) error {
	id := ctx.Params("id")

	apiKey, err := server.Db.GetAPIKeyByID(id)

	if err != nil {
		return response.Error(ctx, 404, "API key not found", err)
	}

	return response.Success(ctx, 200, apiKey)
}

func VerifyAPIKey(server *app.FiberServer, ctx *fiber.Ctx) error {
	var req struct {
		ApiKey string `json:"api_key"`
	}

	if err := ctx.BodyParser(&req); err != nil {
		return response.Error(ctx, 400, "Invalid request body", err)
	}

	if len(req.ApiKey) < 8 {
		return response.Error(ctx, 400, "Malformed API key", nil)
	}

	// Split by prefix
	parts := strings.SplitN(req.ApiKey, "_", 2)
	if len(parts) < 2 {
		return response.Error(ctx, 400, "Invalid API key format", nil)
	}
	prefix := parts[0] + "_"

	apiKey, err := server.Db.GetAPIKeyByPrefix(prefix)
	if err != nil {
		server.Db.TrackUsage("", ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "API key not recognized", nil)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(req.ApiKey)); err != nil {
		server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "Invalid API key", nil)
	}

	if !apiKey.IsActive || (apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now())) {
		server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "API key expired or inactive", nil)
	}

	server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 200)
	server.Db.TrackAudit("api", "verify_key", ctx.IP(), map[string]any{
		"key_id":   apiKey.ID,
		"endpoint": ctx.Path(),
		"valid":    true,
	})

	return response.Success(ctx, 200, fiber.Map{"valid": true})
}

func RevokeAPIKey(s *app.FiberServer, c *fiber.Ctx) error {
	id := c.Params("id")
	if err := s.Db.RevokeAPIKey(id); err != nil {
		return response.Error(c, 404, "API key not found", err)
	}

	s.Db.TrackAudit("system", "revoke_key", c.IP(), map[string]any{"key_id": id})
	return response.Success(c, 200, nil)
}
