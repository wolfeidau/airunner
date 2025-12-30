package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/wolfeidau/airunner/cmd/server/internal/commands"
)

var (
	version = "dev"
	cli     struct {
		Dev       bool `help:"Enable dev mode."`
		Version   kong.VersionFlag
		RPCServer commands.RPCServerCmd `cmd:"" help:"Start the RPC server"`
		Website   commands.WebsiteCmd   `cmd:"" help:"Start the website server"`
	}
)

func main() {
	ctx := context.Background()
	cmd := kong.Parse(&cli,
		kong.Vars{
			"version": version,
		},
		kong.BindTo(ctx, (*context.Context)(nil)))
	err := cmd.Run(&commands.Globals{Dev: cli.Dev, Version: version})
	cmd.FatalIfErrorf(err)
}
