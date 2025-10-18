package handler

import (
	"authcell/internal/app"
	"authcell/internal/database"
	"authcell/internal/server/response"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Creates a cryptographically secure short identifier for keys
func generateShortKeyID(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate key_id: " + err.Error())
	}
	return hex.EncodeToString(b)[:length]
}

func CreateAPIKey(server *app.FiberServer, ctx *fiber.Ctx) error {
	var req struct {
		KeyPrefix string     `json:"key_prefix"`
		ExpiresAt *time.Time `json:"expires_at"`
		RateLimit int        `json:"rate_limit"`
	}

	if err := ctx.BodyParser(&req); err != nil {
		return response.Error(ctx, 400, "Invalid request body", err)
	}

	// Generate a short key_id for fast database lookup
	// 8 chars ~ 32 bits of randomness
	keyID := generateShortKeyID(8)

	// Build the human-visible API key
	fullKey := fmt.Sprintf("%s%s_%s", req.KeyPrefix, keyID, uuid.New().String())

	// Hash full key for secure storage
	hashed, _ := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)

	// Create the DB record
	apiKey := database.APIKey{
		ID:         uuid.New().String(),
		KeyID:      keyID,
		KeyHash:    string(hashed),
		KeyPrefix:  req.KeyPrefix,
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  req.ExpiresAt,
		RateLimit:  req.RateLimit,
		UsageCount: 0,
	}

	// Store the key
	if err := server.Db.CreateAPIKey(apiKey); err != nil {
		return response.Error(ctx, 500, "Failed to create API key", err)
	}

	// Audit log for tracking
	server.Db.TrackAudit("system", "create_key", ctx.IP(), map[string]any{
		"key_record_id": apiKey.ID,
		"key_id":        apiKey.KeyID,
		"prefix":        apiKey.KeyPrefix,
	})

	// Respond with non-sensitive details
	return response.Success(ctx, 201, fiber.Map{
		// Visible only once to client
		"api_key": fullKey,
		"id":      apiKey.ID,
		"key_id":  apiKey.KeyID,
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

	apiKeyStr := strings.TrimSpace(req.ApiKey)
	if len(apiKeyStr) < 8 {
		return response.Error(ctx, 400, "Malformed API key", nil)
	}

	// Extract key structure
	parts := strings.SplitN(apiKeyStr, "_", 3)
	if len(parts) < 3 {
		return response.Error(ctx, 400, "Invalid API key format", nil)
	}

	prefix := parts[0] + "_"
	keyID := parts[1]

	// Lookup key by its unique key_id
	apiKey, err := server.Db.GetAPIKeyByKeyID(keyID)
	if err != nil {
		server.Db.TrackUsage("", ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "API key not recognized", nil)
	}

	// Verify prefix consistency for good measure
	if apiKey.KeyPrefix != prefix {
		server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "API key prefix mismatch", nil)
	}

	// Validate bcrypt hash against supplied key
	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(apiKeyStr)); err != nil {
		server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "Invalid API key", nil)
	}

	// Check if active and not expired
	if !apiKey.IsActive || (apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now())) {
		server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 401)
		return response.Error(ctx, 401, "API key expired or inactive", nil)
	}

	// Log audit & usage
	server.Db.TrackUsage(apiKey.ID, ctx.Path(), ctx.IP(), 200)
	server.Db.TrackAudit("api", "verify_key", ctx.IP(), map[string]any{
		"key_record_id": apiKey.ID,
		"key_id":        apiKey.KeyID,
		"prefix":        apiKey.KeyPrefix,
		"endpoint":      ctx.Path(),
	})

	return response.Success(ctx, 200, fiber.Map{
		"valid": true,
	})
}

func RevokeAPIKey(s *app.FiberServer, c *fiber.Ctx) error {
	id := c.Params("id")
	if err := s.Db.RevokeAPIKey(id); err != nil {
		return response.Error(c, 404, "API key not found", err)
	}

	s.Db.TrackAudit("system", "revoke_key", c.IP(), map[string]any{"key_id": id})
	return response.Success(c, 200, nil)
}
