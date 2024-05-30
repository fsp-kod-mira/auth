package pg

import (
	"auth/internal/entity"
	"context"
	"log/slog"

	"github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
)

// var _ usecase.UserStorage = (*UserStorage)(nil)

type UserStorage struct {
	db *sqlx.DB
}

func NewUserStorage(db *sqlx.DB) *UserStorage {
	return &UserStorage{db: db}
}

func (u *UserStorage) Get(ctx context.Context, id string) (*entity.User, error) {
	log := ctx.Value("logger").(*slog.Logger).With("method", "Get")

	var user entity.User

	query, args, err := squirrel.Select("*").
		From("users").
		Where(squirrel.Eq{"id": id}).
		Limit(1).
		PlaceholderFormat(squirrel.Dollar).
		ToSql()
	if err != nil {
		log.Error("Failed to generate SQL query", slog.String("err", err.Error()))
		return nil, err
	}

	log.Debug("executing query", slog.String("query", query), slog.Any("args", args))

	err = u.db.Get(&user, query, args...)
	if err != nil {
		log.Error("Failed to execute query", slog.String("err", err.Error()))
		return nil, err
	}

	return &user, nil
}

func (u *UserStorage) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	log := ctx.Value("logger").(*slog.Logger).With("method", "GetByEmail")
	var user entity.User
	query, args, err := squirrel.Select("*").
		From("users").
		Where(squirrel.Eq{"email": email}).
		Limit(1).
		PlaceholderFormat(squirrel.Dollar).
		ToSql()
	if err != nil {
		log.Error("Failed to generate SQL query", slog.String("err", err.Error()))
		return nil, err
	}
	log.Debug("executing query", slog.String("query", query), slog.Any("args", args))
	if err := u.db.Get(&user, query, args...); err != nil {
		log.Error("Failed to execute query", slog.String("err", err.Error()))
		return nil, err

	}
	log.Debug("query result user", slog.Any("user", user))
	return &user, nil
}

func (u *UserStorage) Create(ctx context.Context, user *entity.User) error {
	log := ctx.Value("logger").(*slog.Logger).With("method", "Create")

	query, args, err := squirrel.Insert("users").
		Columns("id", "email", "password", "last_name", "first_name", "middle_name", "role").
		Values(user.Id, user.Email, user.Password, user.LastName, user.FirstName, user.MiddleName, user.Role).
		Suffix("RETURNING *").
		PlaceholderFormat(squirrel.Dollar).
		ToSql()
	if err != nil {
		log.Error("failed to generate SQL query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("executing query", slog.String("query", query), slog.Any("args", args))

	if err := u.db.Get(user, query, args...); err != nil {
		log.Error("failed to execute query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("query result user", slog.Any("user", user))
	return nil
}

func (u *UserStorage) Update(ctx context.Context, user *entity.User) error {
	log := ctx.Value("logger").(*slog.Logger).With("method", "Update")

	query, args, err := squirrel.Update("users").
		Set("password", user.Password).
		Where(squirrel.Eq{"id": user.Id}).
		PlaceholderFormat(squirrel.Dollar).
		ToSql()
	if err != nil {
		log.Error("failed to generate SQL query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("executing query", slog.String("query", query), slog.Any("args", args))
	if err := u.db.Get(user, query, args...); err != nil {
		log.Error("failed to execute query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("query result user", slog.Any("user", user))
	return nil
}

func (u *UserStorage) Delete(ctx context.Context, id int) error {
	log := ctx.Value("logger").(*slog.Logger).With("method", "Delete")
	query, args, err := squirrel.Delete("users").
		Where(squirrel.Eq{"id": id}).
		PlaceholderFormat(squirrel.Dollar).
		ToSql()
	if err != nil {
		log.Error("failed to generate SQL query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("executing query", slog.String("query", query), slog.Any("args", args))
	if _, err := u.db.Exec(query, args...); err != nil {
		log.Error("failed to execute query", slog.String("err", err.Error()))
		return err
	}

	log.Debug("successfully deleted user", slog.Any("id", id))

	return nil
}
