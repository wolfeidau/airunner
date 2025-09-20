package commands

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type RPCServerCmd struct {
	Listen string `help:"listen address" default:"localhost:8080"`
	Cert   string `help:"path to TLS cert file" default:"./.certs/cert.pem"`
	Key    string `help:"path to TLS key file" default:"./.certs/key.pem"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Caller().Logger()

	mux := http.NewServeMux()

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("listen", s.Listen).Msg("Listening for RPC connections")

	server := &http.Server{
		Addr:         s.Listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server.ListenAndServeTLS(s.Cert, s.Key)
}
