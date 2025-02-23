package routes

import (
	"github.com/FantomStudy/relation-app/auth-service/controllers"
	"github.com/FantomStudy/relation-app/auth-service/temp/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	authCtrl := controllers.NewAuthController()

	//? Аутентификация и регистрация
	app.Post("/register", authCtrl.Register)
	app.Post("/login", authCtrl.Login)
	app.Post("/logout", middleware.JWTProtected(), authCtrl.Logout)

	//? Сброс пароля
	app.Post("/password/reset/request", authCtrl.RequestPasswordReset)
	app.Post("/password/reset/confirm", authCtrl.ConfirmPasswordReset)

	//? Информация о пользователе
	app.Get("/user/:id", middleware.JWTProtected(), authCtrl.GetUserByID)

	app.Get("/profile", middleware.JWTProtected(), authCtrl.Profile)
	app.Get("/profile/avatar", middleware.JWTProtected(), authCtrl.GetAvatar) //! ДЕБАГ

	//? Изменение профиля пользователя
	app.Put("/profile/name", middleware.JWTProtected(), authCtrl.UpdateName)
	app.Put("/profile/email", middleware.JWTProtected(), authCtrl.UpdateEmail)
	app.Put("/profile/password", middleware.JWTProtected(), authCtrl.UpdatePassword)
	app.Put("/profile/avatar", middleware.JWTProtected(), authCtrl.UpdateAvatar)

	app.Delete("/profile/avatar/delete", middleware.JWTProtected(), authCtrl.DeleteAvatar)
}
