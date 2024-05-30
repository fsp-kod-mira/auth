package app

import (
	"auth/api/auth"
	"auth/internal/config"
	srv "auth/internal/handlers/grpc"
	"auth/internal/interceptors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type App struct {
	cfg *config.Config
	log *slog.Logger

	impl *srv.Server
}

func newApp(cfg *config.Config, log *slog.Logger, impl *srv.Server) *App {
	return &App{
		cfg:  cfg,
		log:  log,
		impl: impl,
	}
}

func (a *App) Run() {
	s := grpc.NewServer(grpc.UnaryInterceptor(interceptors.LoggingInterceptor(a.log)))
	reflection.Register(s)
	auth.RegisterAuthServer(s, a.impl)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)

	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.cfg.App.Host, a.cfg.App.Port))
		if err != nil {
			panic(fmt.Errorf("cannot bind port %d", a.cfg.App.Port))
		}

		a.log.Info("server started", slog.String("host", a.cfg.App.Host), slog.Int("port", a.cfg.App.Port))
		if err := s.Serve(listener); err != nil {
			a.log.Error("caught error on Serve", slog.String("err", err.Error()))
			panic(err)
		}
	}()

	sig := <-sigChan
	s.GracefulStop()
	a.log.Info(fmt.Sprintf("Signal %v received, stopping server...\n", sig))
}
