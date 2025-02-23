package redistore

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
)

var Client *redis.Client

func InitRedis() {
	Client = redis.NewClient(&redis.Options{ //? Настройка клиента Redis
		Addr:     "redis:6379",
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	ctx := context.Background() //? Ожидание подключения к Redis
	for i := 0; i < 10; i++ {
		if _, err := Client.Ping(ctx).Result(); err == nil {
			break
		}
		log.Printf("Retrying Redis connection (%d/10)", i+1)
		time.Sleep(1 * time.Second)
	}
}
