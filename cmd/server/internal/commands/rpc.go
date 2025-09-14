package commands

import (
	"context"
	"net/http"
	"os"

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

	return http.ListenAndServeTLS(s.Listen, s.Cert, s.Key, mux)
}
