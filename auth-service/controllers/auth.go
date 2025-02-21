package controllers

import (
	"os"
	"strings"
	"time"

	"github.com/FantomStudy/relation-app/auth-service/models"
	"github.com/FantomStudy/relation-app/auth-service/shared"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var TokenBlacklist = make(map[string]time.Time)

type AuthController struct {
	DB        *gorm.DB
	Validator *validator.Validate
}

func NewAuthController() *AuthController {
	return &AuthController{
		DB:        shared.Connect(),
		Validator: validator.New(),
	}
}

func (ac *AuthController) Register(c *fiber.Ctx) error {
	var request struct {
		Name     string `json:"name" validate:"required"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=6"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request payload",
		})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var validationErrors []string
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				validationErrors = append(validationErrors, err.Field()+" cannot be empty")
			case "email":
				validationErrors = append(validationErrors, "Invalid email format")
			case "min":
				validationErrors = append(validationErrors, err.Field()+" must be at least "+err.Param()+" characters")
			default:
				validationErrors = append(validationErrors, err.Field()+" is invalid")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": validationErrors})
	}

	var existingUser models.User
	if err := ac.DB.Where("email = ?", request.Email).First(&existingUser).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"error": "Email already exists"})
	} else if err != gorm.ErrRecordNotFound {
		return c.Status(500).JSON(fiber.Map{"error": "Database error: " + err.Error()})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": "Failed to hash password",
		})
	}

	user := models.User{
		Name:     request.Name,
		Email:    request.Email,
		Password: string(hashedPassword),
	}

	if err := ac.DB.Create(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create user: " + err.Error()})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "User registered successfully",
		"user":    user,
	})
}

func (ac *AuthController) Login(c *fiber.Ctx) error {
	var request struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request payload",
		})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, err.Field()+" cannot be empty")
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	var user models.User
	if err := ac.DB.Where("email =?", request.Email).First(&user).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Wrong password",
		})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Logged in successfully",
		"token":   tokenString,
	})
}

func (ac *AuthController) Profile(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)
	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
	})
}

func (ac *AuthController) Logout(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
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
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

	exp, ok := claims["exp"].(float64)
	if !ok {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid expiration in token"})
	}

	TokenBlacklist[tokenString] = time.Unix(int64(exp), 0)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Logged out successfully",
	})
}
