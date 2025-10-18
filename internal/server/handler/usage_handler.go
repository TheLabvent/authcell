package handler

import (
	"authcell/internal/app"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
)

func ListAPIUsage(server *app.FiberServer, ctx *fiber.Ctx) error {
	id := ctx.Params("id")

	usages, err := server.Db.ListUsage(id)
	if err != nil {
		return response.Error(ctx, 404, "No usage records found for the given key ID", err)
	}

	return response.Success(ctx, 200, usages)
}
