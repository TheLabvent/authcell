package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"authcell/internal/database"
	"authcell/internal/keys"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
)

const (
	maxNameLen     = 200
	maxMetadataLen = 8 * 1024
	createAttempts = 3
)

type createKeyRequest struct {
	KeyPrefix string          `json:"key_prefix"`
	Name      string          `json:"name"`
	Metadata  json.RawMessage `json:"metadata"`
	ExpiresAt *time.Time      `json:"expires_at"`
	RateLimit *int            `json:"rate_limit"`
}

// createdKey is returned once, on create and rotate. It is the only time the
// plaintext key is ever available.
type createdKey struct {
	database.APIKey
	Plaintext string `json:"api_key"`
}

func validateMetadata(raw json.RawMessage) (json.RawMessage, string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, ""
	}
	if len(raw) > maxMetadataLen {
		return nil, "metadata must be at most 8KB"
	}
	if raw[0] != '{' {
		return nil, "metadata must be a JSON object"
	}
	return raw, ""
}

// CreateAPIKey handles POST /v1/keys.
func (h *Handler) CreateAPIKey(c *fiber.Ctx) error {
	var req createKeyRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return response.Error(c, fiber.StatusBadRequest, "Invalid request body")
		}
	}

	prefix, err := keys.NormalizePrefix(req.KeyPrefix)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) > maxNameLen {
		return response.Error(c, fiber.StatusBadRequest, "name must be at most 200 characters")
	}
	meta, msg := validateMetadata(req.Metadata)
	if msg != "" {
		return response.Error(c, fiber.StatusBadRequest, msg)
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		return response.Error(c, fiber.StatusBadRequest, "expires_at must be in the future")
	}
	rate := 0
	if req.RateLimit != nil {
		if *req.RateLimit < 0 {
			return response.Error(c, fiber.StatusBadRequest, "rate_limit cannot be negative (0 means unlimited)")
		}
		rate = *req.RateLimit
	}

	ctx, cancel := h.ctx(c)
	defer cancel()

	created, plain, err := h.insertKey(c, database.NewAPIKey{
		KeyPrefix: prefix, Name: req.Name, Metadata: meta, ExpiresAt: req.ExpiresAt, RateLimit: rate,
	})
	if err != nil {
		return response.Internal(c, "Failed to create API key", err)
	}

	h.audit(ctx, c, actorAdmin, "", "create_key", map[string]any{
		"key_record_id": created.ID, "key_id": created.KeyID, "prefix": created.KeyPrefix, "name": created.Name,
	})
	return response.Success(c, fiber.StatusCreated, createdKey{APIKey: created, Plaintext: plain})
}

// insertKey generates a key and stores it, retrying on the (astronomically
// unlikely) event of a key_id collision.
func (h *Handler) insertKey(c *fiber.Ctx, n database.NewAPIKey) (database.APIKey, string, error) {
	ctx, cancel := h.ctx(c)
	defer cancel()
	var lastErr error
	for i := 0; i < createAttempts; i++ {
		gen, err := keys.Generate(n.KeyPrefix)
		if err != nil {
			return database.APIKey{}, "", err
		}
		n.KeyID, n.KeyHash = gen.KeyID, gen.Hash
		k, err := h.DB.CreateAPIKey(ctx, n)
		if err == nil {
			return k, gen.Plaintext, nil
		}
		if !errors.Is(err, database.ErrDuplicate) {
			return database.APIKey{}, "", err
		}
		lastErr = err
	}
	return database.APIKey{}, "", lastErr
}

// ListAPIKeys handles GET /v1/keys?limit=&offset=&active=&prefix=.
func (h *Handler) ListAPIKeys(c *fiber.Ctx) error {
	limit, ok := pageSize(c)
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "limit must be a positive integer")
	}
	offset, ok := nonNegInt64(c, "offset")
	if !ok {
		return response.Error(c, fiber.StatusBadRequest, "offset must be a non-negative integer")
	}
	f := database.KeyFilter{Limit: limit, Offset: int(offset), Prefix: strings.TrimSpace(c.Query("prefix"))}
	if raw := c.Query("active"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return response.Error(c, fiber.StatusBadRequest, "active must be true or false")
		}
		f.Active = &b
	}

	ctx, cancel := h.ctx(c)
	defer cancel()
	list, total, err := h.DB.ListAPIKeys(ctx, f)
	if err != nil {
		return response.Internal(c, "Failed to list API keys", err)
	}
	return response.List(c, list, fiber.Map{"total": total, "limit": limit, "offset": offset})
}

// GetAPIKey handles GET /v1/keys/:id.
func (h *Handler) GetAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if !validUUID(id) {
		return response.Error(c, fiber.StatusBadRequest, "id must be a UUID")
	}
	ctx, cancel := h.ctx(c)
	defer cancel()
	k, err := h.DB.GetAPIKeyByID(ctx, id)
	if errors.Is(err, database.ErrNotFound) {
		return response.Error(c, fiber.StatusNotFound, "API key not found")
	}
	if err != nil {
		return response.Internal(c, "Failed to fetch API key", err)
	}
	return response.Success(c, fiber.StatusOK, k)
}

type updateKeyRequest struct {
	Name      *string         `json:"name"`
	Metadata  json.RawMessage `json:"metadata"`
	ExpiresAt json.RawMessage `json:"expires_at"`
	RateLimit *int            `json:"rate_limit"`
}

// UpdateAPIKey handles PATCH /v1/keys/:id. Send "expires_at": null to remove expiry.
func (h *Handler) UpdateAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if !validUUID(id) {
		return response.Error(c, fiber.StatusBadRequest, "id must be a UUID")
	}
	var req updateKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request body")
	}

	var u database.APIKeyUpdate
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if len(name) > maxNameLen {
			return response.Error(c, fiber.StatusBadRequest, "name must be at most 200 characters")
		}
		u.Name = &name
	}
	if len(req.Metadata) > 0 {
		meta, msg := validateMetadata(req.Metadata)
		if msg != "" {
			return response.Error(c, fiber.StatusBadRequest, msg)
		}
		if meta == nil {
			meta = json.RawMessage("{}")
		}
		u.Metadata = meta
	}
	if raw := bytes.TrimSpace(req.ExpiresAt); len(raw) > 0 {
		if bytes.Equal(raw, []byte("null")) {
			u.ClearExpires = true
		} else {
			var t time.Time
			if err := json.Unmarshal(raw, &t); err != nil {
				return response.Error(c, fiber.StatusBadRequest, "expires_at must be an RFC 3339 timestamp or null")
			}
			if !t.After(time.Now()) {
				return response.Error(c, fiber.StatusBadRequest, "expires_at must be in the future")
			}
			u.ExpiresAt = &t
		}
	}
	if req.RateLimit != nil {
		if *req.RateLimit < 0 {
			return response.Error(c, fiber.StatusBadRequest, "rate_limit cannot be negative (0 means unlimited)")
		}
		u.RateLimit = req.RateLimit
	}

	ctx, cancel := h.ctx(c)
	defer cancel()
	k, err := h.DB.UpdateAPIKey(ctx, id, u)
	if errors.Is(err, database.ErrNotFound) {
		return response.Error(c, fiber.StatusNotFound, "API key not found")
	}
	if err != nil {
		return response.Internal(c, "Failed to update API key", err)
	}
	h.audit(ctx, c, actorAdmin, "", "update_key", map[string]any{"key_record_id": k.ID, "key_id": k.KeyID})
	return response.Success(c, fiber.StatusOK, k)
}

// RevokeAPIKey handles DELETE /v1/keys/:id.
func (h *Handler) RevokeAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if !validUUID(id) {
		return response.Error(c, fiber.StatusBadRequest, "id must be a UUID")
	}
	ctx, cancel := h.ctx(c)
	defer cancel()
	k, err := h.DB.RevokeAPIKey(ctx, id)
	if errors.Is(err, database.ErrNotFound) {
		return response.Error(c, fiber.StatusNotFound, "API key not found")
	}
	if err != nil {
		return response.Internal(c, "Failed to revoke API key", err)
	}
	h.audit(ctx, c, actorAdmin, "", "revoke_key", map[string]any{"key_record_id": k.ID, "key_id": k.KeyID})
	return response.Success(c, fiber.StatusOK, k)
}

// RotateAPIKey handles POST /v1/keys/:id/rotate. It issues a new key with the
// same settings and revokes the old one.
func (h *Handler) RotateAPIKey(c *fiber.Ctx) error {
	id := c.Params("id")
	if !validUUID(id) {
		return response.Error(c, fiber.StatusBadRequest, "id must be a UUID")
	}
	ctx, cancel := h.ctx(c)
	defer cancel()

	old, err := h.DB.GetAPIKeyByID(ctx, id)
	if errors.Is(err, database.ErrNotFound) {
		return response.Error(c, fiber.StatusNotFound, "API key not found")
	}
	if err != nil {
		return response.Internal(c, "Failed to fetch API key", err)
	}
	if !old.IsActive {
		return response.Error(c, fiber.StatusConflict, "Cannot rotate a revoked key")
	}
	expires := old.ExpiresAt
	if expires != nil && !expires.After(time.Now()) {
		expires = nil
	}

	created, plain, err := h.insertKey(c, database.NewAPIKey{
		KeyPrefix: strings.TrimRight(old.KeyPrefix, "_"), Name: old.Name, Metadata: old.Metadata,
		ExpiresAt: expires, RateLimit: old.RateLimit,
	})
	if err != nil {
		return response.Internal(c, "Failed to create replacement key", err)
	}
	if _, err := h.DB.RevokeAPIKey(ctx, old.ID); err != nil {
		return response.Internal(c, "Created replacement key but failed to revoke the old one", err)
	}

	h.audit(ctx, c, actorAdmin, "", "rotate_key", map[string]any{
		"old_key_record_id": old.ID, "new_key_record_id": created.ID, "key_id": created.KeyID,
	})
	return response.Success(c, fiber.StatusCreated, createdKey{APIKey: created, Plaintext: plain})
}
