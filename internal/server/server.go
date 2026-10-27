// Package server wires middleware and routes into a Fiber app.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"
	"time"

	"authcell/internal/config"
	"authcell/internal/database"
	"authcell/internal/server/handler"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
)

const bodyLimit = 64 * 1024

// New builds the HTTP app.
func New(cfg config.Config, db database.Service, version string) *fiber.App {
	fcfg := fiber.Config{
		AppName:               "authcell",
		BodyLimit:             bodyLimit,
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          15 * time.Second,
		IdleTimeout:           60 * time.Second,
		DisableStartupMessage: true,
		ErrorHandler:          errorHandler,
	}
	if len(cfg.TrustedProxies) > 0 {
		fcfg.ProxyHeader = fiber.HeaderXForwardedFor
		fcfg.EnableTrustedProxyCheck = true
		fcfg.TrustedProxies = cfg.TrustedProxies
	}
	app := fiber.New(fcfg)

	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(requestLogger)
	app.Use(securityHeaders)
	if cfg.CORSOrigins != "" {
		app.Use(cors.New(cors.Config{
			AllowOrigins: cfg.CORSOrigins,
			AllowMethods: "GET,POST,PATCH,DELETE,OPTIONS",
			AllowHeaders: "Accept,Authorization,Content-Type,X-API-Key",
			MaxAge:       300,
		}))
	}

	h := handler.New(db, cfg.RateLimitWindow, cfg.RequestTimeout, version)
	admin := bearerAuth(cfg.AdminToken)

	v1 := app.Group("/v1")
	v1.Get("/health", h.Health)

	// Verify is the hot path called by your services. It is open unless
	// AUTHCELL_VERIFY_TOKEN is set; the admin token is also accepted.
	verifyAuth := func(c *fiber.Ctx) error { return c.Next() }
	if cfg.VerifyToken != "" {
		verifyAuth = bearerAuth(cfg.VerifyToken, cfg.AdminToken)
	}
	v1.Post("/keys/verify", verifyAuth, h.VerifyAPIKey)

	keys := v1.Group("/keys", admin)
	keys.Post("/", h.CreateAPIKey)
	keys.Get("/", h.ListAPIKeys)
	keys.Get("/:id", h.GetAPIKey)
	keys.Patch("/:id", h.UpdateAPIKey)
	keys.Delete("/:id", h.RevokeAPIKey)
	keys.Post("/:id/rotate", h.RotateAPIKey)

	v1.Get("/usage/:id", admin, h.ListAPIUsage)
	v1.Get("/audit", admin, h.ListAuditLog)

	app.Use(func(c *fiber.Ctx) error {
		return response.Error(c, fiber.StatusNotFound, "Route not found")
	})
	return app
}

// bearerAuth accepts "Authorization: Bearer <token>" matching any of tokens.
// Tokens are hashed before comparison so length differences don't leak.
func bearerAuth(tokens ...string) fiber.Handler {
	var digests [][32]byte
	for _, t := range tokens {
		if t != "" {
			digests = append(digests, sha256.Sum256([]byte(t)))
		}
	}
	return func(c *fiber.Ctx) error {
		auth := c.Get(fiber.HeaderAuthorization)
		const scheme = "bearer "
		if len(auth) <= len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
			c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="authcell"`)
			return response.Error(c, fiber.StatusUnauthorized, "Missing bearer token")
		}
		got := sha256.Sum256([]byte(strings.TrimSpace(auth[len(scheme):])))
		match := 0
		for _, d := range digests {
			match |= subtle.ConstantTimeCompare(got[:], d[:])
		}
		if match != 1 {
			return response.Error(c, fiber.StatusUnauthorized, "Invalid bearer token")
		}
		return c.Next()
	}
}

func securityHeaders(c *fiber.Ctx) error {
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Cache-Control", "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Next()
}

func requestLogger(c *fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	if err != nil {
		// Let the error handler write the response so the logged status is right.
		if hErr := c.App().ErrorHandler(c, err); hErr != nil {
			_ = c.SendStatus(fiber.StatusInternalServerError)
		}
		err = nil
	}
	status := c.Response().StatusCode()
	level := slog.LevelInfo
	if status >= 500 {
		level = slog.LevelError
	}
	slog.Log(c.UserContext(), level, "request",
		"method", c.Method(),
		"path", c.Path(),
		"status", status,
		"duration_ms", time.Since(start).Milliseconds(),
		"ip", c.IP(),
		"request_id", c.Locals("requestid"),
	)
	return err
}

func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "Internal server error"
	var fe *fiber.Error
	if errors.As(err, &fe) {
		code = fe.Code
		msg = fe.Message
	} else {
		slog.Error("unhandled error", "error", err, "path", c.Path())
	}
	return response.Error(c, code, msg)
}
