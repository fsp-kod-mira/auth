//go:build wireinject
// +build wireinject

package app

import (
	"auth/internal/config"
	"auth/internal/handlers/grpc"
	"auth/internal/storage/pg"
	"auth/internal/usecase"
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	ts "auth/internal/storage/redis"

	"github.com/google/wire"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

func Init() (*App, func(), error) {
	panic(
		wire.Build(
			newApp,
			wire.NewSet(config.New),
			wire.NewSet(initLogger),
			wire.NewSet(initDB),
			wire.NewSet(initRedis),

			// storages
			wire.NewSet(pg.NewUserStorage),
			wire.NewSet(ts.NewTokenStorage),

			// usecase
			wire.NewSet(usecase.New),
			wire.Bind(new(usecase.TokenStorage), new(*ts.TokenStorage)),
			wire.Bind(new(usecase.UserStorage), new(*pg.UserStorage)),

			// handlers
			wire.NewSet(grpc.New),
			wire.Bind(new(grpc.AuthUseCase), new(*usecase.UseCase)),
			wire.Bind(new(grpc.UserUseCase), new(*usecase.UseCase)),
		),
	)
}

func initLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level

	switch cfg.Logger.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func initDB(cfg *config.Config, log *slog.Logger) (*sqlx.DB, func(), error) {
	host := cfg.DB.Host
	port := cfg.DB.Port
	user := cfg.DB.User
	pass := cfg.DB.Pass
	name := cfg.DB.Name

	cs := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", user, pass, host, port, name)

	log.Info("connecting to database", slog.String("conn", cs))

	db, err := sqlx.Open("postgres", cs)
	if err != nil {
		return nil, nil, err
	}

	if err := db.Ping(); err != nil {
		log.Error("failed to connect to database", slog.String("err", err.Error()), slog.String("conn", cs))
		return nil, func() { db.Close() }, err
	}

	log.Info("connected to database", slog.String("conn", cs))

	return db, func() { db.Close() }, nil
}

func initRedis(cfg *config.Config, log *slog.Logger) (*redis.Client, func(), error) {
	host := cfg.Redis.Host
	port := cfg.Redis.Port
	pass := cfg.Redis.Pass
	db := cfg.Redis.DB

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: pass,
		DB:       db,
	})

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)

	log.Info("connecting to redis", slog.Int("db", db), slog.String("host", host), slog.Int("port", port))

	if _, err := client.Ping(ctx).Result(); err != nil {
		log.Error("failed to connect to redis", slog.String("err", err.Error()), slog.Int("db", db), slog.String("host", host), slog.Int("port", port))
		return nil, func() { client.Close() }, err
	}

	log.Info("connected to redis", slog.Int("db", db), slog.String("host", host), slog.Int("port", port))

	return client, func() { client.Close() }, nil
}
