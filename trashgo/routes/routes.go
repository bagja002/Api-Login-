
package routes

import (
	
	"github.com/gofiber/fiber"
)

func Setup(app *fiber.App) {

	app.Post("/api/register")
	app.Post("/api/login")
	app.Get("/api/user")
	app.Post("/api/logout")
}