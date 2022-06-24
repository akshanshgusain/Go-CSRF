package models

import (
	"github.com/akshanshgusain/Go-CSRF/utils"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type User struct {
	Username, PasswordHash, Role string
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

func GenerateCSRFSecret() (string, error) {
	return utils.GenerateRandomString(32)
}
