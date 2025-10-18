package app

import (
	"authcell/internal/database"

	"github.com/gofiber/fiber/v2"
)

type FiberServer struct {
	*fiber.App
	Db database.Service
}

func NewFiberServer() *FiberServer {
	server := &FiberServer{
		App: fiber.New(fiber.Config{
			ServerHeader: "authcell",
			AppName:      "authcell",
		}),

		Db: database.New(),
	}

	// Ensure tables/schema exist at startup
	if err := server.Db.EnsureSchema(); err != nil {
		panic("database schema creation failed: " + err.Error())
	}

	return server
}
