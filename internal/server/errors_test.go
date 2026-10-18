package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestToConnectError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code connect.Code
	}{
		{"invalid token", store.ErrInvalidTaskToken, connect.CodeInvalidArgument},
		{"invalid argument", store.ErrInvalidArgument, connect.CodeInvalidArgument},
		{"job id mismatch", store.ErrJobIDMismatch, connect.CodeInvalidArgument},
		{"queue mismatch", store.ErrQueueMismatch, connect.CodeInvalidArgument},
		{"event too large", store.ErrEventTooLarge, connect.CodeResourceExhausted},
		{"job not found", store.ErrJobNotFound, connect.CodeNotFound},
		{"lease lost", store.ErrLeaseLost, connect.CodeFailedPrecondition},
		{"conflict", store.ErrConflict, connect.CodeAlreadyExists},
		{"unavailable", store.ErrUnavailable, connect.CodeUnavailable},
		{"deadline", context.DeadlineExceeded, connect.CodeDeadlineExceeded},
		{"canceled", context.Canceled, connect.CodeCanceled},
		{"wrapped lease lost", fmt.Errorf("op: %w", fmt.Errorf("%w: detail", store.ErrLeaseLost)), connect.CodeFailedPrecondition},
		{"wrapped invalid argument", fmt.Errorf("%w: bad", store.ErrInvalidArgument), connect.CodeInvalidArgument},
		{"wrapped deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), connect.CodeDeadlineExceeded},
		{"connect passthrough", connect.NewError(connect.CodeUnauthenticated, errors.New("nope")), connect.CodeUnauthenticated},
		{"wrapped connect passthrough", fmt.Errorf("x: %w", connect.NewError(connect.CodeUnimplemented, errors.New("nope"))), connect.CodeUnimplemented},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.code, connect.CodeOf(toConnectError(tt.err)))
		})
	}

	t.Run("nil", func(t *testing.T) {
		require.NoError(t, toConnectError(nil))
	})

	t.Run("unknown is generic internal", func(t *testing.T) {
		got := toConnectError(errors.New("pq: secret detail"))
		require.Equal(t, connect.CodeInternal, connect.CodeOf(got))
		require.NotContains(t, got.Error(), "secret")
	})
}
