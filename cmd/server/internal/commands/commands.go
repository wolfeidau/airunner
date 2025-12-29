package commands

import (
	"net/http"
	"time"
)

type Globals struct {
	Dev     bool
	Version string
}

func configureHTTPServer(addr string, handler http.Handler) *http.Server {
	// Create HTTP server
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}
}
