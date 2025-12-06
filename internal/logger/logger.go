package logger

import (
	"context"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
)

func Setup(dev bool) zerolog.Logger {
	var logger zerolog.Logger
	level := zerolog.InfoLevel
	if dev {
		level = zerolog.DebugLevel
	}

	logger = zerolog.New(os.Stderr).Level(level).With().Timestamp().Caller().Logger()

	if dev {
		logger = logger.Output(zerolog.ConsoleWriter{Out: os.Stderr, FormatTimestamp: func(i any) string {
			return time.Now().Format(time.RFC3339)
		}}).Level(level).With().Stack().Logger()
	}

	return logger
}

var _ connect.Interceptor = (*ConnectRequests)(nil)

type ConnectRequests struct {
	logger zerolog.Logger
}

func NewConnectRequests(logger zerolog.Logger) *ConnectRequests {
	return &ConnectRequests{logger: logger}
}

func (c *ConnectRequests) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(
		ctx context.Context,
		req connect.AnyRequest,
	) (connect.AnyResponse, error) {
		started := time.Now()

		ctx = c.logger.With().
			Str("protocol", req.Peer().Protocol).
			Str("addr", req.Peer().Addr).
			Logger().WithContext(ctx)

		resp, err := next(ctx, req)

		if err != nil {
			zerolog.Ctx(ctx).Error().
				Err(err).
				Dur("duration", time.Since(started)).
				Msg("rpc call")

			return resp, err
		}

		zerolog.Ctx(ctx).Info().
			Dur("duration", time.Since(started)).
			Msg("rpc call")

		return resp, err
	})
}

func (c *ConnectRequests) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(
		ctx context.Context,
		spec connect.Spec,
	) connect.StreamingClientConn {
		started := time.Now()
		ctx = c.logger.With().Logger().WithContext(ctx)

		conn := next(ctx, spec)

		zerolog.Ctx(ctx).Info().
			Dur("duration", time.Since(started)).
			Msg("rpc client stream finished")

		return conn
	})
}

func (c *ConnectRequests) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(
		ctx context.Context,
		conn connect.StreamingHandlerConn,
	) error {
		started := time.Now()

		ctx = c.logger.With().
			Str("protocol", conn.Peer().Protocol).
			Str("addr", conn.Peer().Addr).
			Logger().WithContext(ctx)

		err := next(ctx, conn)
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("rpc server stream error")
			return err
		}

		zerolog.Ctx(ctx).Info().
			Dur("duration", time.Since(started)).
			Msg("rpc server stream finished")

		return nil
	})
}
