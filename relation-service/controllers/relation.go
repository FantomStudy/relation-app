package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/FantomStudy/relation-app/relation-service/models"
	"github.com/FantomStudy/relation-app/relation-service/shared"
	"github.com/FantomStudy/relation-app/relation-service/temp/redistore"
	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/skip2/go-qrcode"
	"gorm.io/gorm"
)

type NotificationMessage struct {
	Type      string `json:"type"`
	UserID    uint   `json:"user_id"`
	PartnerID uint   `json:"partner_id"`
}

type RelationController struct {
	DB        *gorm.DB
	Validator *validator.Validate
}

func NewRelationController() *RelationController {
	redistore.InitRedis()

	return &RelationController{
		DB:        shared.Connect(),
		Validator: validator.New(),
	}
}

func (rc *RelationController) GeneratePairCode(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var pair models.Pair
	if err := rc.DB.Where("user_id = ? OR partner_id = ?", userID, userID).First(&pair).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"error": "User is already in a pair"})
	} else if err != gorm.ErrRecordNotFound {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	code := fmt.Sprintf("%d-%s", userID, time.Now().Format("20060102150405"))

	ctx := context.Background()
	if err := redistore.Client.Set(ctx, "pair:code:"+code, userID, 24*time.Hour).Err(); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to store pair code"})
	}

	baseURL := os.Getenv("RELATION_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:3001"
	}

	qrData := fmt.Sprintf("%s/pair/create?code=%s", baseURL, code)
	qr, err := qrcode.Encode(qrData, qrcode.Medium, 256)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate QR code"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"code":    code,
		"qr_code": qr,
	})
}

func (rc *RelationController) CreatePair(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	code := c.Query("code")
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Code is required"})
	}

	var pair models.Pair
	if err := rc.DB.Where("user_id = ? OR partner_id = ?", userID, userID).First(&pair).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"error": "You are already in a pair"})
	} else if err != gorm.ErrRecordNotFound {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	ctx := context.Background()
	partnerID, err := redistore.Client.Get(ctx, "pair:code:"+code).Uint64()
	if err == redis.Nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid or expired code"})
	} else if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to verify code"})
	}

	if err := rc.DB.Where("user_id = ? OR partner_id = ?", partnerID, partnerID).First(&pair).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"error": "Partner is already in a pair", "code": err})
	} else if err != gorm.ErrRecordNotFound {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	if userID == uint(partnerID) {
		return c.Status(400).JSON(fiber.Map{"error": "Cannot pair with yourself"})
	}

	newPair := models.Pair{
		UserID:    userID,
		PartnerID: uint(partnerID),
	}
	if err := rc.DB.Create(&newPair).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create pair"})
	}

	if err := redistore.Client.Del(ctx, "pair:code:"+code).Err(); err != nil {
		log.Printf("Failed to delete pair code: %v", err)
	}

	message := NotificationMessage{
		Type:      "pairCreated",
		UserID:    userID,
		PartnerID: uint(partnerID),
	}
	msgBytes, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal notification: %v", err)
	} else if err := redistore.Client.Publish(context.Background(), "notifications", msgBytes).Err(); err != nil {
		log.Printf("Failed to publish notification: %v", err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Pair created successfully",
		"pair_id": newPair.ID,
	})
}

func (rc *RelationController) DeletePair(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var pair models.Pair
	if err := rc.DB.Where("user_id = ? OR partner_id = ?", userID, userID).First(&pair).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(fiber.Map{"message": "No pair found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	partnerID := pair.PartnerID
	if pair.PartnerID == userID {
		partnerID = pair.UserID
	}

	if err := rc.DB.Delete(&pair).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete pair"})
	}

	// Отправка уведомления через Redis
	message := NotificationMessage{
		Type:      "pairDeleted",
		UserID:    userID,
		PartnerID: partnerID,
	}
	msgBytes, _ := json.Marshal(message)
	if err := redistore.Client.Publish(context.Background(), "notifications", msgBytes).Err(); err != nil {
		log.Printf("Failed to publish notification: %v", err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Pair deleted successfully",
	})
}

func (rc *RelationController) GetPair(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var pair models.Pair
	if err := rc.DB.Where("user_id = ? OR partner_id = ?", userID, userID).First(&pair).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(fiber.Map{"message": "No pair found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	partnerID := pair.PartnerID
	if pair.PartnerID == userID {
		partnerID = pair.UserID
	}

	authURL := os.Getenv("AUTH_SERVICE_URL")
	if authURL == "" {
		authURL = "http://localhost:3000"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/user/%d", authURL, partnerID), nil)
	if err != nil {
		log.Printf("Failed to create request to AuthService: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch partner data"})
	}
	req.Header.Set("Authorization", c.Get("Authorization"))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch partner data from AuthService: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch partner data"})
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("AuthService returned non-200 status: %d", resp.StatusCode)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch partner data"})
	}

	var partner struct {
		ID        uint   `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&partner); err != nil {
		log.Printf("Failed to decode partner data: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decode partner data"})
	}

	return c.JSON(fiber.Map{
		"pair_id": pair.ID,
		"partner": fiber.Map{
			"id":         partner.ID,
			"name":       partner.Name,
			"email":      partner.Email,
			"avatar_url": partner.AvatarURL,
		},
		"created_at": pair.CreatedAt,
		"updated_at": pair.UpdatedAt,
	})
}

func (rc *RelationController) AddFriend(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uint)

    var request struct {
        FriendID uint `json:"friend_id" validate:"required"`
    }
    if err := c.BodyParser(&request); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
    }
    if err := rc.Validator.Struct(request); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Friend ID is required"})
    }

    if userID == request.FriendID {
        return c.Status(400).JSON(fiber.Map{"error": "Cannot add yourself as a friend"})
    }

    // Проверяем, не является ли пользователь уже другом
    var friendship models.Friend
    if err := rc.DB.Where("user_id = ? AND friend_id = ?", userID, request.FriendID).First(&friendship).Error; err == nil {
        return c.Status(400).JSON(fiber.Map{"error": "This user is already your friend"})
    } else if err != gorm.ErrRecordNotFound {
        log.Printf("Database error checking friendship: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "Database error"})
    }

    newFriend := models.Friend{
        UserID:    userID,
        FriendID:  request.FriendID,
        UpdatedAt: time.Now(),
    }
    if err := rc.DB.Create(&newFriend).Error; err != nil {
        log.Printf("Failed to add friend: UserID=%d, FriendID=%d, Error=%v", userID, request.FriendID, err)
        return c.Status(500).JSON(fiber.Map{"error": "Failed to add friend"})
    }

    // Отправка уведомления через Redis
    message := common.NotificationMessage{
        Type:      "friendAdded",
        UserID:    userID,
        PartnerID: request.FriendID,
    }
    msgBytes, err := json.Marshal(message)
    if err != nil {
        log.Printf("Failed to marshal notification: %v", err)
    } else if err := redistore.Client.Publish(context.Background(), "notifications", msgBytes).Err(); err != nil {
        log.Printf("Failed to publish notification: %v", err)
    }

    return c.JSON(fiber.Map{
        "success":  true,
        "message":  "Friend added successfully",
        "friend_id": newFriend.ID,
    })
}

// GetFriends возвращает список друзей пользователя
func (rc *RelationController) GetFriends(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uint)

    var friends []models.Friend
    if err := rc.DB.Where("user_id = ?", userID).Find(&friends).Error; err != nil {
        log.Printf("Database error fetching friends: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "Database error"})
    }

    if len(friends) == 0 {
        return c.JSON(fiber.Map{"friends": []interface{}{}})
    }

    // Собираем ID друзей для запроса к AuthService
    friendIDs := make([]uint, len(friends))
    for i, f := range friends {
        friendIDs[i] = f.FriendID
    }

    // Запрос данных о друзьях из AuthService
    var friendDetails []struct {
        ID        uint   `json:"id"`
        Name      string `json:"name"`
        Email     string `json:"email"`
        AvatarURL string `json:"avatar_url"`
    }
    client := &http.Client{Timeout: 10 * time.Second}
    for _, friendID := range friendIDs {
        req, err := http.NewRequest("GET", fmt.Sprintf("http://auth-service:3000/v1/user/%d", friendID), nil)
        if err != nil {
            log.Printf("Failed to create request to AuthService for friend %d: %v", friendID, err)
            continue
        }
        req.Header.Set("Authorization", c.Get("Authorization"))

        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Failed to fetch friend data from AuthService for friend %d: %v", friendID, err)
            continue
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            log.Printf("AuthService returned non-200 status for friend %d: %d", friendID, resp.StatusCode)
            continue
        }

        var friendData struct {
            ID        uint   `json:"id"`
            Name      string `json:"name"`
            Email     string `json:"email"`
            AvatarURL string `json:"avatar_url"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&friendData); err != nil {
            log.Printf("Failed to decode friend data for friend %d: %v", friendID, err)
            continue
        }
        friendDetails = append(friendDetails, friendData)
    }

    return c.JSON(fiber.Map{
        "friends": friendDetails,
    })
}

// DeleteFriend удаляет друга
func (rc *RelationController) DeleteFriend(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uint)

    var request struct {
        FriendID uint `json:"friend_id" validate:"required"`
    }
    if err := c.BodyParser(&request); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request payload"})
    }
    if err := rc.Validator.Struct(request); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Friend ID is required"})
    }

    var friendship models.Friend
    if err := rc.DB.Where("user_id = ? AND friend_id = ?", userID, request.FriendID).First(&friendship).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return c.Status(404).JSON(fiber.Map{"error": "Friendship not found"})
        }
        log.Printf("Database error finding friendship: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "Database error"})
    }

    friendship.UpdatedAt = time.Now()
    if err := rc.DB.Save(&friendship).Error; err != nil {
        log.Printf("Failed to update friendship before deletion: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "Failed to update friendship"})
    }
    if err := rc.DB.Delete(&friendship).Error; err != nil {
        log.Printf("Failed to delete friend: %v", err)
        return c.Status(500).JSON(fiber.Map{"error": "Failed to delete friend"})
    }

    message := common.NotificationMessage{
        Type:      "friendDeleted",
        UserID:    userID,
        PartnerID: request.FriendID,
    }
    msgBytes, err := json.Marshal(message)
    if err != nil {
        log.Printf("Failed to marshal notification: %v", err)
    } else if err := redistore.Client.Publish(context.Background(), "notifications", msgBytes).Err(); err != nil {
        log.Printf("Failed to publish notification: %v", err)
    }

    return c.JSON(fiber.Map{
        "success": true,
        "message": "Friend deleted successfully",
    })
}