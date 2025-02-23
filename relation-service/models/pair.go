package models

import (
	"gorm.io/gorm"
)

type Pair struct {
	gorm.Model
	UserID    uint `gorm:"not null;index;foreignKey:ID;references:users(id);constraint:OnDelete:CASCADE" json:"user_id"`
	PartnerID uint `gorm:"not null;index;foreignKey:ID;references:users(id);constraint:OnDelete:CASCADE" json:"partner_id"`
}
