package main

import (
	"github.com/FantomStudy/relation-app/relation-service/routes"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	routes.SetupRoutes(app)

	app.Listen(":3001")
}
