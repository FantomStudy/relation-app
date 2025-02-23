package controllers

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FantomStudy/relation-app/auth-service/models"
	"github.com/FantomStudy/relation-app/auth-service/shared"
	"github.com/FantomStudy/relation-app/auth-service/temp/redistore"
	"github.com/FantomStudy/relation-app/auth-service/utils"
	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// TODO: Переделать механизм сброса пароля через email или telegram

type AuthController struct {
	DB        *gorm.DB
	Validator *validator.Validate
}

func NewAuthController() *AuthController {
	redistore.InitRedis()

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
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { //? Проверка метода хеширования
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid signing method")
		}

		return []byte(os.Getenv("JWT_SECRET")), nil //? Проверка секретного ключа
	})

	if err != nil || !token.Valid { //? Не те данные в токене или истёк
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	claims, ok := token.Claims.(jwt.MapClaims) //? Проверка claims на соответствие ожидаемым полям
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token claims",
		})
	}

	exp, ok := claims["exp"].(float64) //? Проверка истечения срока действия токена
	if !ok {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid expiration in token"})
	}

	ctx := context.Background()
	ttl := time.Until(time.Unix(int64(exp), 0)) //? Удаление как только истечёт
	if ttl <= 0 {
		ttl = time.Second
	}

	if err := redistore.Client.Set(ctx, tokenString, "revoked", ttl).Err(); err != nil { //? Блокировка токена в Redis
		return c.Status(500).JSON(fiber.Map{"error": "Failed to revoke token" + err.Error()})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Logged out successfully",
	})
}

func (ac *AuthController) Profile(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{
		"id":         user.ID,
		"name":       user.Name,
		"email":      user.Email,
		"avatar_url": user.AvatarURL,
	})
}

func (ac *AuthController) GetUserByID(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var user models.User
	if err := ac.DB.First(&user, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(fiber.Map{
		"id":         user.ID,
		"name":       user.Name,
		"email":      user.Email,
		"avatar_url": user.AvatarURL,
	})
}

func (ac *AuthController) UpdateName(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var request struct {
		Name string `json:"name" validate:"required"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			if err.Tag() == "required" {
				errors = append(errors, "Name cannot be empty")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	user.Name = request.Name
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update name"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Name updated successfully",
		"name":    user.Name,
	})
}

func (ac *AuthController) UpdateEmail(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var request struct {
		Email string `json:"email" validate:"required,email"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				errors = append(errors, "Email cannot be empty")
			case "email":
				errors = append(errors, "Invalid email format")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	var existingUser models.User
	if err := ac.DB.Where("email = ? AND id != ?", request.Email, userID).First(&existingUser).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"error": "Email already exists"})
	} else if err != gorm.ErrRecordNotFound {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	user.Email = request.Email
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update email"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Email updated successfully",
		"email":   user.Email,
	})
}

func (ac *AuthController) UpdatePassword(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var request struct {
		OldPassword string `json:"old_password" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=6"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				errors = append(errors, err.Field()+" cannot be empty")
			case "min":
				errors = append(errors, "New password must be at least "+err.Param()+" characters")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.OldPassword)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Incorrect old password"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash new password"})
	}

	user.Password = string(hashedPassword)
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Password updated successfully",
	})
}

func (ac *AuthController) UpdateAvatar(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	file, err := c.FormFile("avatar")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Failed to upload avatar file"})
	}

	if file.Size > 10*1024*1024 {
		return c.Status(400).JSON(fiber.Map{"error": "Avatar file too large (max 5MB)"})
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
		return c.Status(400).JSON(fiber.Map{"error": "Only PNG and JPEG files are allowed"})
	}

	uploadDir := "./uploads/avatars"
	avatarPath := fmt.Sprintf("%s/avatar_%d%s", uploadDir, userID, ext)
	if err := c.SaveFile(file, avatarPath); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save avatar"})
	}

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	user.AvatarURL = strings.TrimPrefix(avatarPath, ".")
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update avatar URL"})
	}

	return c.JSON(fiber.Map{
		"success":    true,
		"message":    "Avatar updated successfully",
		"avatar_url": user.AvatarURL,
	})
}

func (ac *AuthController) DeleteAvatar(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	defaultAvatar := "/uploads/avatars/default.jpg"
	if user.AvatarURL == defaultAvatar {
		return c.JSON(fiber.Map{
			"success":    true,
			"message":    "Avatar is already default",
			"avatar_url": user.AvatarURL,
		})
	}

	if err := os.Remove("." + user.AvatarURL); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to delete avatar file: %v", err)
	}

	user.AvatarURL = defaultAvatar
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to reset avatar URL"})
	}

	return c.JSON(fiber.Map{
		"success":    true,
		"message":    "Avatar deleted successfully",
		"avatar_url": user.AvatarURL,
	})
}

func (ac *AuthController) GetAvatar(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	// Проверка, существует ли файл
	avatarPath := "." + user.AvatarURL
	if _, err := os.Stat(avatarPath); os.IsNotExist(err) {
		// Если файла нет, возвращаем дефолтный аватар или ошибку
		return c.SendFile("./uploads/avatars/default.jpg")
	}

	// Отправка файла клиенту
	return c.SendFile(avatarPath)
}

// ! НЕБЕЗОПАСНО
func (ac *AuthController) RequestPasswordReset(c *fiber.Ctx) error {
	var request struct {
		Email string `json:"email" validate:"required,email"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				errors = append(errors, "Email cannot be empty")
			case "email":
				errors = append(errors, "Invalid email format")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	var user models.User
	if err := ac.DB.Where("email = ?", request.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(fiber.Map{"success": false, "message": "User does not exist"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	// Генерация 6-значного кода
	code, err := utils.GenerateResetCode()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate reset code"})
	}

	// Сохранение кода в Redis
	ctx := context.Background()
	key := fmt.Sprintf("reset:%s", code)
	if err := redistore.Client.Set(ctx, key, user.ID, 15*time.Minute).Err(); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to store reset code"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Reset code generated",
		"code":    code,
	})
}
func (ac *AuthController) ConfirmPasswordReset(c *fiber.Ctx) error {
	var request struct {
		Code        string `json:"code" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=6"`
	}
	if err := c.BodyParser(&request); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := ac.Validator.Struct(request); err != nil {
		var errors []string
		for _, err := range err.(validator.ValidationErrors) {
			switch err.Tag() {
			case "required":
				errors = append(errors, err.Field()+" cannot be empty")
			case "len":
				errors = append(errors, "Code must be exactly 6 digits")
			case "min":
				errors = append(errors, "New password must be at least "+err.Param()+" characters")
			}
		}
		return c.Status(400).JSON(fiber.Map{"errors": errors})
	}

	// Проверка кода в Redis
	ctx := context.Background()
	key := fmt.Sprintf("reset:%s", request.Code)
	userID, err := redistore.Client.Get(ctx, key).Uint64()
	if err == redis.Nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired reset code"})
	} else if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to verify code"})
	}

	// Обновление пароля
	var user models.User
	if err := ac.DB.First(&user, userID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to hash new password"})
	}

	user.Password = string(hashedPassword)
	if err := ac.DB.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update password"})
	}

	// Удаление кода из Redis
	if err := redistore.Client.Del(ctx, key).Err(); err != nil {
		log.Printf("Failed to delete reset code: %v", err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Password reset successfully",
	})
}
