package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name      string `json:"name"`
	Email     string `gorm:"unique; not null" json:"email"`
	Password  string `gorm:"not null" json:"-"`
	AvatarURL string `gorm:"default:'/uploads/avatars/default.jpg'"`
}
