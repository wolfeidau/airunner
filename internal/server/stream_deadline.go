package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"
)

type writeDeadlineKey struct{}

// writeDeadlineSetter sets (or, with the zero time, clears) the write deadline of the
// connection carrying the current request.
type writeDeadlineSetter func(time.Time) error

// WithWriteDeadline exposes the response write deadline to streaming handlers. It must
// sit innermost in the middleware chain so it sees a ResponseWriter that is, or unwraps
// to, the real one; wrappers that hide it make the deadline unsupported, which handlers
// treat as "no per-send deadline".
func WithWriteDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		ctx := context.WithValue(r.Context(), writeDeadlineKey{}, writeDeadlineSetter(rc.SetWriteDeadline))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeDeadlineFromContext(ctx context.Context) writeDeadlineSetter {
	set, _ := ctx.Value(writeDeadlineKey{}).(writeDeadlineSetter)
	return set
}

// deadlineSender applies a per-send write deadline around send.
type deadlineSender struct {
	set           writeDeadlineSetter
	timeout       time.Duration
	disabled      bool
	onUnsupported func()
}

// do runs send under a write deadline. It reports whether send failed after the
// deadline had passed, which is how a stalled reader surfaces.
func (d *deadlineSender) do(send func() error) (stalled bool, err error) {
	if d.disabled || d.set == nil || d.timeout <= 0 {
		return false, send()
	}
	deadline := time.Now().Add(d.timeout)
	if serr := d.set(deadline); serr != nil {
		if errors.Is(serr, http.ErrNotSupported) {
			d.disabled = true
			d.onUnsupported()
		}
		return false, send()
	}
	if err := send(); err != nil {
		return errors.Is(err, os.ErrDeadlineExceeded) || !time.Now().Before(deadline), err
	}
	_ = d.set(time.Time{})
	return false, nil
}
