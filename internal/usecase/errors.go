package usecase

import "errors"

var (
	ErrInvalidRole        = errors.New("invalid role")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrSessionNotFound    = errors.New("session not found")
	ErrTokenExpired       = errors.New("session expired")
)
