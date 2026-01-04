package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/wolfeidau/airunner/cmd/server/internal/commands"
)

var (
	version = "dev"
	cli     struct {
		Debug   bool `help:"Enable debug mode."`
		Version kong.VersionFlag
		Server  commands.WebsiteCmd `cmd:"" help:"Start the server (website + API)"`
	}
)

func main() {
	ctx := context.Background()
	cmd := kong.Parse(&cli,
		kong.Vars{
			"version": version,
		},
		kong.BindTo(ctx, (*context.Context)(nil)))
	err := cmd.Run(&commands.Globals{Debug: cli.Debug, Version: version})
	cmd.FatalIfErrorf(err)
}
