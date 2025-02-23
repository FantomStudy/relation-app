package main

import (
	"context"
	"encoding/json"
	"log"
	"strconv"

	"github.com/FantomStudy/relation-app/notification-service/temp/redistore"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
)

type WebSocketClient struct {
	Conn   *websocket.Conn
	UserID uint
}

type WebSocketHub struct {
	clients   map[*WebSocketClient]bool
	broadcast chan NotificationMessage
}

type NotificationMessage struct {
	Type      string `json:"type"`
	UserID    uint   `json:"user_id"`
	PartnerID uint   `json:"partner_id"`
}

var hub = &WebSocketHub{
	clients:   make(map[*WebSocketClient]bool),
	broadcast: make(chan NotificationMessage),
}

func main() {
	app := fiber.New()
	redistore.InitRedis()

	// Запуск WebSocket-хаба
	go func() {
		for msg := range hub.broadcast {
			for client := range hub.clients {
				if msg.Type == "pairCreated" && (client.UserID == msg.UserID || client.UserID == msg.PartnerID) ||
					msg.Type == "pairDeleted" && client.UserID == msg.PartnerID {

					message, err := json.Marshal(msg)
					if err != nil {
						log.Printf("Failed to marshal message: %v", err)
						continue
					}
					if err := client.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
						log.Printf("WebSocket error: %v", err)
						client.Conn.Close()
						delete(hub.clients, client)
					}
				}
			}
		}
	}()

	// Подписка на Redis Pub/Sub
	ctx := context.Background()
	pubsub := redistore.Client.Subscribe(ctx, "notifications")
	defer pubsub.Close()

	go func() {
		for msg := range pubsub.Channel() {
			var notification NotificationMessage
			if err := json.Unmarshal([]byte(msg.Payload), &notification); err != nil {
				log.Printf("Failed to unmarshal notification: %v", err)
				continue
			}
			hub.broadcast <- notification
		}
	}()

	// WebSocket-эндпоинт
	app.Get("/ws", websocket.New(func(c *websocket.Conn) {
		userIDStr := c.Query("user_id")
		if userIDStr == "" {
			log.Println("user_id is required")
			return
		}
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			log.Println("Invalid user_id")
			return
		}

		client := &WebSocketClient{Conn: c, UserID: uint(userID)}
		hub.clients[client] = true
		log.Printf("Client connected: %v, UserID: %d", c.RemoteAddr(), userID)

		defer func() {
			delete(hub.clients, client)
			c.Close()
			log.Printf("Client disconnected: %v", c.RemoteAddr())
		}()

		for {
			if _, _, err := c.ReadMessage(); err != nil {
				break
			}
		}
	}))

	app.Listen(":5000")
}
