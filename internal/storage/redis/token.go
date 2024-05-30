package redis

import (
	"auth/internal/config"
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenStorage struct {
	cfg    *config.Config
	client *redis.Client
}

func NewTokenStorage(cfg *config.Config, client *redis.Client) *TokenStorage {
	return &TokenStorage{client: client, cfg: cfg}
}

func (t TokenStorage) Get(ctx context.Context, userId string) (string, error) {
	log := ctx.Value("logger").(*slog.Logger)

	log.Debug("getting token for user", slog.String("userId", userId))
	cmd := t.client.Get(ctx, userId)

	if cmd.Err() != nil {
		log.Error("error getting token", slog.String("error", cmd.Err().Error()))
		return "", cmd.Err()
	}

	return cmd.Val(), nil
}

func (t TokenStorage) Save(ctx context.Context, userId string, token string) error {
	log := ctx.Value("logger").(*slog.Logger)

	log.Debug("saving token for user",
		slog.String("userId", userId),
		slog.String("expiresAt", time.Now().Add(time.Duration(t.cfg.JWT.Refresh.TTL)*time.Minute).Format(time.RFC3339)),
	)

	cmd := t.client.Set(ctx, userId, token, time.Duration(t.cfg.JWT.Refresh.TTL)*time.Minute)

	if cmd.Err() != nil {
		log.Error("error saving token", slog.String("error", cmd.Err().Error()))
		return cmd.Err()
	}

	return nil
}

func (t TokenStorage) Delete(ctx context.Context, userId string) error {
	log := ctx.Value("logger").(*slog.Logger)

	log.Debug("deleting token for user", slog.String("userId", userId))
	cmd := t.client.Del(ctx, userId)

	if cmd.Err() != nil {
		log.Error("error deleting token", slog.String("error", cmd.Err().Error()))
		return cmd.Err()
	}

	return nil
}
