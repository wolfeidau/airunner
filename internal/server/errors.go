package server

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// toConnectError maps a store or context error to a Connect error.
// Lease and not-found messages stay generic so callers cannot tell which check
// failed. Unknown errors are logged and returned as a generic internal error.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}

	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr
	}

	switch {
	case errors.Is(err, store.ErrInvalidTaskToken),
		errors.Is(err, store.ErrInvalidArgument),
		errors.Is(err, store.ErrJobIDMismatch),
		errors.Is(err, store.ErrQueueMismatch):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, store.ErrEventTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, store.ErrJobNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrLeaseLost):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, store.ErrConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, store.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	}

	log.Error().Err(err).Msg("Unhandled error in RPC handler")
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}
