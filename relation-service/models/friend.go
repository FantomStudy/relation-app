package models

import "gorm.io/gorm"

type Friend struct {
	gorm.Model
	UserID   uint `gorm:"not null;index;foreignKey:ID;references:users(id);constraint:OnDelete:CASCADE" json:"user_id"`
	FriendID uint `gorm:"not null;index;foreignKey:ID;references:users(id);constraint:OnDelete:CASCADE" json:"friend_id"`
}
