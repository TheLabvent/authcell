// Package response defines the JSON envelope every AuthCell endpoint returns.
package response

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
)

type Response struct {
	Status    string `json:"status"`
	Code      int    `json:"code"`
	Message   string `json:"message,omitempty"`
	Data      any    `json:"data,omitempty"`
	Meta      any    `json:"meta,omitempty"`
	Error     any    `json:"error,omitempty"`
	TimeStamp int64  `json:"timestamp"`
}

// Success writes a success envelope.
func Success(c *fiber.Ctx, code int, data any) error {
	return c.Status(code).JSON(Response{
		Status:    "success",
		Code:      code,
		Data:      data,
		TimeStamp: time.Now().Unix(),
	})
}

// List writes a success envelope with pagination metadata.
func List(c *fiber.Ctx, data any, meta any) error {
	return c.Status(fiber.StatusOK).JSON(Response{
		Status:    "success",
		Code:      fiber.StatusOK,
		Data:      data,
		Meta:      meta,
		TimeStamp: time.Now().Unix(),
	})
}

// Error writes an error envelope. message is shown to clients, so it must not
// contain internal details.
func Error(c *fiber.Ctx, code int, message string) error {
	return ErrorWithData(c, code, message, nil)
}

// ErrorWithData writes an error envelope that also carries a data payload.
func ErrorWithData(c *fiber.Ctx, code int, message string, data any) error {
	return c.Status(code).JSON(Response{
		Status:    "error",
		Code:      code,
		Message:   message,
		Data:      data,
		TimeStamp: time.Now().Unix(),
	})
}

// Internal logs the real error server side and returns a generic 500.
func Internal(c *fiber.Ctx, msg string, err error) error {
	slog.Error(msg, "error", err, "path", c.Path(), "request_id", c.Locals("requestid"))
	return Error(c, fiber.StatusInternalServerError, msg)
}
