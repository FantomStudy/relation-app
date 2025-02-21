package routes

import (
	"github.com/FantomStudy/relation-app/auth-service/controllers"
	"github.com/FantomStudy/relation-app/auth-service/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	authCtrl := controllers.NewAuthController()

	// Authentication routes

	app.Post("/register", authCtrl.Register)
	app.Post("/login", authCtrl.Login)

	// Auth protected routes
	app.Post("/logout", middleware.JWTProtected(), authCtrl.Logout)

	app.Get("/profile", middleware.JWTProtected(), authCtrl.Profile)

	app.Put("/profile/name", middleware.JWTProtected(), authCtrl.UpdateName)
	app.Put("/profile/email", middleware.JWTProtected(), authCtrl.UpdateEmail)
	app.Put("/profile/password", middleware.JWTProtected(), authCtrl.UpdatePassword)

}
