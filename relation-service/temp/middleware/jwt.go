package middleware

import (
	"context"
	"os"
	"strings"

	"github.com/FantomStudy/relation-app/relation-service/temp/redistore"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTProtected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization") //? Токен из заголовка Authorization (Authorization: Bearer <token>)
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Token not provided",
			})
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token format",
			})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		ctx := context.Background() //? Проверка токена в черном списке Redis
		if exists, err := redistore.Client.Exists(ctx, tokenString).Result(); err == nil && exists > 0 {
			return c.Status(401).JSON(fiber.Map{"error": "Token has been revoked"})
		} else if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to check token: " + err.Error()})
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { //? Парсинг токена и проверка подлинности
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid signing method")
			}

			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		userID, ok := claims["user_id"].(float64)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid user ID in token",
			})
		}
		c.Locals("userID", uint(userID)) //? Сохранение userID в контексте для дальнейшего использования

		return c.Next()
	}
}
