package routes

import (
	"github.com/FantomStudy/relation-app/auth-service/controllers"
	"github.com/FantomStudy/relation-app/auth-service/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	authCtrl := controllers.NewAuthController()

	app.Post("/register", authCtrl.Register)
	app.Post("/login", authCtrl.Login)
	app.Get("/profile", middleware.JWTProtected(), authCtrl.Profile)
}
