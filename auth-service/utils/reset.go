package utils

import (
	"crypto/rand"
	"fmt"
)

func GenerateResetCode() (string, error) {
	//? Генерируем 3 байта
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	//? Преобразуем 3 байта в число от 0 до 999999 и форматируем как 6 цифр
	code := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return fmt.Sprintf("%06d", code%1000000), nil
}
