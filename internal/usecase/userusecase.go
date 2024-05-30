package usecase

import (
	"auth/internal/entity"
	"context"
	"database/sql"
	"errors"
	"log/slog"
)

func (u *UseCase) FindById(ctx context.Context, id string) (*entity.User, error) {
	log := ctx.Value("logger").(*slog.Logger).With(slog.String("method", "FindById"))

	log.Debug("find user by id", slog.String("id", id))
	user, err := u.userStorage.Get(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	log.Debug("user found", slog.String("user", user.Email))

	return user, nil
}
