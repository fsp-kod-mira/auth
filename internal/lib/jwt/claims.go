package jwt

import (
	"auth/internal/entity"

	"github.com/golang-jwt/jwt/v5"
)

type claims struct {
	entity.UserClaims
	jwt.RegisteredClaims
}
