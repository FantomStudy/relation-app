package routes

import (
	"github.com/FantomStudy/relation-app/relation-service/controllers"
	"github.com/FantomStudy/relation-app/relation-service/temp/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	rlCtrl := controllers.NewRelationController()

	app.Post("/pair/code", middleware.JWTProtected(), rlCtrl.GeneratePairCode)
	app.Post("/pair/create", middleware.JWTProtected(), rlCtrl.CreatePair)

	app.Get("/pair", middleware.JWTProtected(), rlCtrl.GetPair)
	app.Delete("/pair", middleware.JWTProtected(), rlCtrl.DeletePair)
}
