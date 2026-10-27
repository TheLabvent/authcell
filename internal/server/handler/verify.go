package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"authcell/internal/database"
	"authcell/internal/keys"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
)

// Verification failure reasons. "invalid" covers every case where the caller
// did not prove they hold the key, so nothing leaks about which keys exist.
const (
	ReasonInvalid     = "invalid"
	ReasonRevoked     = "revoked"
	ReasonExpired     = "expired"
	ReasonRateLimited = "rate_limited"
)

type verifyFailure struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type rateInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Reset     time.Time `json:"reset"`
}

type verifySuccess struct {
	Valid     bool            `json:"valid"`
	ID        string          `json:"id"`
	KeyID     string          `json:"key_id"`
	KeyPrefix string          `json:"key_prefix"`
	Name      string          `json:"name"`
	Metadata  json.RawMessage `json:"metadata"`
	ExpiresAt *time.Time      `json:"expires_at"`
	RateLimit *rateInfo       `json:"rate_limit"`
}

// VerifyAPIKey handles POST /v1/keys/verify. The key may be sent as
// {"api_key": "..."} or in the X-API-Key header.
func (h *Handler) VerifyAPIKey(c *fiber.Ctx) error {
	var req struct {
		APIKey string `json:"api_key"`
	}
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return response.Error(c, fiber.StatusBadRequest, "Invalid request body")
		}
	}
	presented := strings.TrimSpace(req.APIKey)
	if presented == "" {
		presented = strings.TrimSpace(c.Get("X-API-Key"))
	}
	if presented == "" {
		return response.Error(c, fiber.StatusBadRequest, "api_key is required")
	}

	ctx, cancel := h.ctx(c)
	defer cancel()

	fail := func(keyRecordID string, status int, reason string) error {
		h.usage(ctx, c, keyRecordID, status)
		msg := "Invalid API key"
		switch reason {
		case ReasonRevoked:
			msg = "API key has been revoked"
		case ReasonExpired:
			msg = "API key has expired"
		case ReasonRateLimited:
			msg = "Rate limit exceeded"
		}
		return response.ErrorWithData(c, status, msg, verifyFailure{Valid: false, Reason: reason})
	}

	parsed, err := keys.Parse(presented)
	if err != nil {
		return fail("", fiber.StatusUnauthorized, ReasonInvalid)
	}

	k, err := h.DB.GetAPIKeyByKeyID(ctx, parsed.KeyID)
	if errors.Is(err, database.ErrNotFound) {
		// Hash anyway so a miss costs about the same as a wrong secret.
		_ = keys.Hash(presented)
		return fail("", fiber.StatusUnauthorized, ReasonInvalid)
	}
	if err != nil {
		return response.Internal(c, "Failed to verify API key", err)
	}

	ok, legacy := keys.Compare(k.KeyHash, presented)
	if !ok || !keys.PrefixMatches(parsed.Prefix, k.KeyPrefix) {
		return fail(k.ID, fiber.StatusUnauthorized, ReasonInvalid)
	}
	if legacy {
		// Move bcrypt hashes from older versions to the fast format.
		if err := h.DB.UpgradeKeyHash(ctx, k.ID, keys.Hash(presented)); err != nil {
			slog.Warn("hash upgrade failed", "key_id", k.KeyID, "error", err)
		}
	}

	if !k.IsActive {
		return fail(k.ID, fiber.StatusUnauthorized, ReasonRevoked)
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(time.Now()) {
		return fail(k.ID, fiber.StatusUnauthorized, ReasonExpired)
	}

	use, err := h.DB.RecordUse(ctx, k.ID, h.RateLimitWindow)
	if err != nil {
		return response.Internal(c, "Failed to record key usage", err)
	}

	var rate *rateInfo
	if use.RateLimit > 0 {
		remaining := use.RateLimit - use.WindowCount
		if remaining < 0 {
			remaining = 0
		}
		rate = &rateInfo{Limit: use.RateLimit, Remaining: remaining, Reset: use.WindowReset.UTC()}
		c.Set("X-RateLimit-Limit", strconv.Itoa(use.RateLimit))
		c.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Set("X-RateLimit-Reset", strconv.FormatInt(use.WindowReset.Unix(), 10))
		if use.WindowCount > use.RateLimit {
			retry := int(time.Until(use.WindowReset).Seconds()) + 1
			if retry < 1 {
				retry = 1
			}
			c.Set(fiber.HeaderRetryAfter, strconv.Itoa(retry))
			return fail(k.ID, fiber.StatusTooManyRequests, ReasonRateLimited)
		}
	}

	h.usage(ctx, c, k.ID, fiber.StatusOK)
	return response.Success(c, fiber.StatusOK, verifySuccess{
		Valid: true, ID: k.ID, KeyID: k.KeyID, KeyPrefix: strings.TrimRight(k.KeyPrefix, "_"),
		Name: k.Name, Metadata: k.Metadata, ExpiresAt: k.ExpiresAt, RateLimit: rate,
	})
}
