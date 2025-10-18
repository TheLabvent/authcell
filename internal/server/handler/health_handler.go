package handler

import (
	"authcell/internal/app"

	"github.com/gofiber/fiber/v2"
)

func HealthHandler(server *app.FiberServer, ctx *fiber.Ctx) error {
	return ctx.JSON(server.Db.Health())
}
