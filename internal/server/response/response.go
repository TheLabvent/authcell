package response

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

type Response struct {
	Status    string `json:"status"`
	Code      int    `json:"code"`
	Message   string `json:"message,omitempty"`
	Data      any    `json:"data,omitempty"`
	Error     any    `json:"error,omitempty"`
	TimeStamp int64  `json:"timestamp"`
}

// Success — standard success response
func Success(c *fiber.Ctx, code int, data any) error {
	return c.Status(code).JSON(Response{
		Status:    "success",
		Code:      code,
		Data:      data,
		TimeStamp: time.Now().Unix(),
	})
}

// Error — standard error handler
func Error(c *fiber.Ctx, code int, message string, err error) error {
	var errorMessage any
	if err != nil {
		errorMessage = err.Error()
	}
	return c.Status(code).JSON(Response{
		Status:    "error",
		Code:      code,
		Message:   message,
		Error:     errorMessage,
		TimeStamp: time.Now().Unix(),
	})
}
