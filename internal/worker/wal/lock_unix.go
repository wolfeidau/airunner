//go:build darwin || linux

package wal

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile takes an exclusive, non-blocking flock on f.
// The lock is tied to the open file description, so it is released when f is
// closed and conflicts with any other open of the same file, including within
// the same process.
func tryLockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // fd fits in int
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrWALLocked
		}
		return err
	}
}
