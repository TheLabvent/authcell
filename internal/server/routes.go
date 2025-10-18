package server

import (
	"authcell/internal/app"
	"authcell/internal/server/handler"
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func RegisterFiberRoutes(server *app.FiberServer) {
	server.App.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS,PATCH",
		AllowHeaders: "Accept,Authorization,Content-Type",
		MaxAge:       300,
	}))

	v1 := server.App.Group("/v1")

	v1.Get("/health", func(ctx *fiber.Ctx) error {
		return handler.HealthHandler(server, ctx)
	})

	keys := v1.Group("/keys")
	keys.Post("/", func(ctx *fiber.Ctx) error { return handler.CreateAPIKey(server, ctx) })
	keys.Get("/:id", func(ctx *fiber.Ctx) error { return handler.GetAPIKey(server, ctx) })
	keys.Post("/verify", func(ctx *fiber.Ctx) error { return handler.VerifyAPIKey(server, ctx) })
	keys.Delete("/:id", func(ctx *fiber.Ctx) error { return handler.RevokeAPIKey(server, ctx) })

	usage := v1.Group("/usage")
	usage.Get("/:id", func(ctx *fiber.Ctx) error { return handler.ListAPIUsage(server, ctx) })

	audit := v1.Group("/audit")
	audit.Get("/", func(ctx *fiber.Ctx) error { return handler.ListAuditLog(server, ctx) })

	stack, _ := json.MarshalIndent(server.App.Stack(), "", "  ")
	fmt.Println(string(stack))
}
