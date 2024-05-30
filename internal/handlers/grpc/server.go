package grpc

import (
	"auth/api/auth"
	"auth/internal/config"
	"auth/internal/entity"
	"auth/internal/usecase"
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lop "github.com/samber/lo/parallel"
)

var _ auth.AuthServer = (*Server)(nil)

type AuthUseCase interface {
	SignUp(ctx context.Context, user *entity.User) (*entity.Tokens, error)
	SignIn(ctx context.Context, user *entity.User) (*entity.Tokens, error)
	SingOut(ctx context.Context, accessToken string) error
	Authenticate(ctx context.Context, accessToken string, role []entity.Role) (*entity.UserClaims, error)
	Refresh(ctx context.Context, refreshToken string) (*entity.Tokens, error)
}

type UserUseCase interface {
	FindById(ctx context.Context, id string) (*entity.User, error)
}

type Server struct {
	cfg *config.Config

	auc AuthUseCase
	uuc UserUseCase

	auth.UnimplementedAuthServer
}

func New(cfg *config.Config, uc AuthUseCase, uuc UserUseCase) *Server {
	return &Server{
		cfg: cfg,
		auc: uc,
		uuc: uuc,
	}
}

func (s *Server) SignIn(ctx context.Context, request *auth.SignInRequest) (*auth.Tokens, error) {
	user := &entity.User{
		UserCredentials: entity.UserCredentials{
			Email:    request.Email,
			Password: request.Password,
		},
	}

	tokens, err := s.auc.SignIn(ctx, user)
	if err != nil {
		if errors.Is(err, usecase.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		if errors.Is(err, usecase.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.Tokens{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
	}, nil
}

func (s *Server) SignUp(ctx context.Context, request *auth.SignUpRequest) (*auth.Tokens, error) {
	user := &entity.User{
		UserCredentials: entity.UserCredentials{
			Email:    request.Email,
			Password: request.Password,
		},
		LastName:   request.LastName,
		FirstName:  request.FirstName,
		MiddleName: request.MiddleName,
		Role:       request.Role.String(),
	}

	tokens, err := s.auc.SignUp(ctx, user)
	if err != nil {
		if errors.Is(err, usecase.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.Tokens{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
	}, nil
}

func (s *Server) SignOut(ctx context.Context, request *auth.SignOutRequest) (*auth.Empty, error) {
	err := s.auc.SingOut(ctx, request.AccessToken)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}

		if errors.Is(err, usecase.ErrSessionNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.Empty{}, nil
}

func (s *Server) Auth(ctx context.Context, request *auth.AuthRequest) (*auth.AuthResponse, error) {
	claims, err := s.auc.Authenticate(ctx, request.AccessToken, lop.Map(request.Roles, func(r auth.Role, _ int) entity.Role {
		return entity.Role(r.String())
	}))
	if err != nil {
		if errors.Is(err, usecase.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}

		if errors.Is(err, usecase.ErrInvalidRole) {
			return nil, status.Error(codes.PermissionDenied, "invalid role")
		}

		if errors.Is(err, usecase.ErrSessionNotFound) {
			return nil, status.Error(codes.NotFound, "session not found")
		}

		if errors.Is(err, usecase.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.AuthResponse{
		UserId: claims.Id,
		Role:   auth.Role(claims.Role.Int()),
	}, nil
}

func (s *Server) Refresh(ctx context.Context, request *auth.RefreshRequest) (*auth.Tokens, error) {
	log := ctx.Value("logger").(*slog.Logger).With("method", "Refresh")

	tokens, err := s.auc.Refresh(ctx, request.RefreshToken)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidToken) {
			log.Debug("invalid token")
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}

		if errors.Is(err, usecase.ErrSessionNotFound) {
			log.Debug("session not found")
			return nil, status.Error(codes.NotFound, "session not found")
		}

		log.Debug("internal server error", slog.String("err", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.Tokens{
		Access:  tokens.Access,
		Refresh: tokens.Refresh,
	}, nil
}

func (s *Server) FindUserById(ctx context.Context, request *auth.FindUserByIdRequest) (*auth.User, error) {
	user, err := s.uuc.FindById(ctx, request.Id)
	if err != nil {
		if errors.Is(err, usecase.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.User{
		Id:         user.Id,
		LastName:   user.LastName,
		FirstName:  user.FirstName,
		MiddleName: user.MiddleName,
		Email:      user.Email,
	}, nil
}

func (s *Server) FindUsersByIds(ctx context.Context, request *auth.FindUsersByIdsRequest) (*auth.FindUsersByIdsResponse, error) {
	uu := make([]*auth.User, 0)

	for _, id := range request.Ids {
		user, err := s.uuc.FindById(ctx, id)
		if err != nil {
			if errors.Is(err, usecase.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}

			return nil, status.Error(codes.Internal, err.Error())
		}

		uu = append(uu, &auth.User{
			Id:         user.Id,
			Email:      user.Email,
			LastName:   user.LastName,
			FirstName:  user.FirstName,
			MiddleName: user.MiddleName,
		})
	}

	return &auth.FindUsersByIdsResponse{
		Users: uu,
	}, nil
}
