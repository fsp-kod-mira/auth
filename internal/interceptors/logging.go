package interceptors

import (
	"context"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"log/slog"
)

func LoggingInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		id := uuid.New().String()

		ctx = context.WithValue(ctx, "logger", log.With("request_id", id))

		log.Info("new grpc request", slog.String("method", info.FullMethod), slog.String("id", id))
		resp, err := handler(ctx, req)
		return resp, err
	}
}
