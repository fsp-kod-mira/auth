package usecase

import (
	"auth/internal/config"
	"auth/internal/entity"
	"auth/internal/lib/jwt"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	lo "github.com/samber/lo"
	"golang.org/x/crypto/bcrypt"
)

type UserStorage interface {
	Get(ctx context.Context, id string) (*entity.User, error)
	GetByEmail(ctx context.Context, email string) (*entity.User, error)

	Create(ctx context.Context, user *entity.User) error
	Update(ctx context.Context, user *entity.User) error
	Delete(ctx context.Context, id int) error
}

type TokenStorage interface {
	Get(ctx context.Context, userId string) (string, error)
	Save(ctx context.Context, userId string, token string) error
	Delete(ctx context.Context, userId string) error
}

// var _ grpc.AuthUseCase = (*UseCase)(nil)
type UseCase struct {
	cfg *config.Config

	userStorage  UserStorage
	tokenStorage TokenStorage
}

func New(cfg *config.Config, userStorage UserStorage, tokenStorage TokenStorage) *UseCase {
	return &UseCase{
		userStorage:  userStorage,
		tokenStorage: tokenStorage,
		cfg:          cfg,
	}
}

func (s *UseCase) SignUp(ctx context.Context, user *entity.User) (*entity.Tokens, error) {
	log := ctx.Value("logger").(*slog.Logger)

	log = log.With(slog.String("method", "SignUp"), slog.String("email", user.Email))

	if _, err := s.userStorage.GetByEmail(ctx, user.Email); err == nil {
		log.Error("phone is already in use")
		return nil, ErrUserAlreadyExists
	}

	userId, err := uuid.NewV7()
	if err != nil {
		log.Error("failed to create uuid", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to generate uuid: %v", err)
	}

	user.Id = userId.String()

	tokens, err := s.generateJwtPair(user.GetClaims())
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt pair: %v", err)
	}

	log.Debug("generated jwt pair", slog.String("access", tokens.Access), slog.String("refresh", tokens.Refresh))

	if err := s.tokenStorage.Save(ctx, user.Id, tokens.Refresh); err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %v", err)
	}

	log.Debug("saved refresh token")

	user.Password, err = s.hashPassword(user.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	if err := s.userStorage.Create(ctx, user); err != nil {

		if e, ok := err.(*pq.Error); ok {
			switch e.Code {
			case "23505":
				log.Error("duplicated data", slog.String("error", e.Message))
				return nil, ErrUserAlreadyExists
			}
		}

		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return tokens, nil
}

func (s *UseCase) SignIn(ctx context.Context, user *entity.User) (*entity.Tokens, error) {
	log := ctx.Value("logger").(*slog.Logger).With(slog.String("method", "SignIn"))

	u, err := s.userStorage.GetByEmail(ctx, user.Email)
	if err != nil {
		log.Error("failed to get user by phone", slog.String("error", err.Error()))
		return nil, ErrInvalidCredentials
	}

	if err := s.verifyPassword(u.Password, user.Password); err != nil {
		log.Error("invalid password", slog.String("err", err.Error()))
		return nil, ErrInvalidCredentials
	}

	tokens, err := s.generateJwtPair(u.GetClaims())
	if err != nil {
		log.Error("failed to generate jwt pair", slog.String("err", err.Error()))
		return nil, fmt.Errorf("failed to generate jwt pair: %v", err)
	}

	if err := s.tokenStorage.Save(ctx, u.Id, tokens.Refresh); err != nil {
		log.Error("failed to save refresh token", slog.String("err", err.Error()))
		return nil, fmt.Errorf("failed to save refresh token: %v", err)
	}

	return tokens, nil
}

func (s *UseCase) SingOut(ctx context.Context, accessToken string) error {
	log := ctx.Value("logger").(*slog.Logger).With(slog.String("method", "SingOut"))

	claims, err := jwt.Validate(accessToken, s.cfg.JWT.Access.Secret)
	if err != nil {
		log.Error("failed to validate access token", slog.String("err", err.Error()))
		return fmt.Errorf("failed to validate access token: %v", err)
	}

	if _, err := s.tokenStorage.Get(ctx, claims.Id); err != nil {
		log.Error("session not found", slog.String("err", err.Error()))
		return ErrSessionNotFound
	}

	return s.tokenStorage.Delete(ctx, claims.Id)
}

func (s *UseCase) Authenticate(ctx context.Context, accessToken string, roles []entity.Role) (*entity.UserClaims, error) {
	log := ctx.Value("logger").(*slog.Logger).With(slog.String("method", "Authenticate"))

	claims, err := jwt.Validate(accessToken, s.cfg.JWT.Access.Secret)
	if err != nil {
		log.Error("failed to validate access token", slog.String("err", err.Error()))

		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}

		return nil, ErrInvalidToken
	}

	u, err := s.userStorage.Get(ctx, claims.Id)
	if err != nil {
		log.Error("failed to get user: %v", err)
		return nil, ErrUserNotFound
	}

	if _, err := s.tokenStorage.Get(ctx, claims.Id); err != nil {
		log.Error("session not found", slog.String("err", err.Error()))
		return nil, ErrSessionNotFound
	}

	log.Info("ready to check role", slog.Any("roles", roles), slog.String("user_role", u.Role))

	if len(roles) > 0 && u.Role != entity.RoleAdmin && !lo.Contains(roles, entity.Role(u.Role)) {
		log.Error("forbidden", slog.Any("roles", roles), slog.String("user_role", u.Role))
		return nil, ErrInvalidRole
	}

	return claims, nil
}

func (s *UseCase) Refresh(ctx context.Context, refreshToken string) (*entity.Tokens, error) {
	claims, err := jwt.Validate(refreshToken, s.cfg.JWT.Refresh.Secret)
	if err != nil {
		log.Printf("failed to validate refresh token: %v", err)
		return nil, ErrInvalidToken
	}

	tokens, err := s.generateJwtPair(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt pair: %v", err)
	}

	if err := s.tokenStorage.Save(ctx, claims.Id, tokens.Refresh); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %v", err)
	}

	return tokens, nil
}

func (s *UseCase) generateJwtPair(claims *entity.UserClaims) (*entity.Tokens, error) {
	refresh, err := jwt.Generate(claims, time.Duration(s.cfg.JWT.Refresh.TTL)*time.Minute, []byte(s.cfg.JWT.Refresh.Secret))
	if err != nil {
		return nil, err
	}

	access, err := jwt.Generate(claims, time.Duration(s.cfg.JWT.Access.TTL)*time.Minute, []byte(s.cfg.JWT.Access.Secret))
	if err != nil {
		return nil, err
	}

	return &entity.Tokens{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (s *UseCase) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (s *UseCase) verifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
