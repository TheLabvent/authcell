package handler

import (
	"authcell/internal/app"
	"authcell/internal/server/response"

	"github.com/gofiber/fiber/v2"
)

func ListAuditLog(server *app.FiberServer, ctx *fiber.Ctx) error {
	logs, err := server.Db.ListAuditLog()
	if err != nil {
		return response.Error(ctx, 500, "Failed to fetch audit logs", err)
	}

	return response.Success(ctx, 200, logs)
}
