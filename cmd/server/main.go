package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/wolfeidau/airunner/cmd/server/internal/commands"
)

var (
	version = "dev"
	cli     struct {
		RPCServer commands.RPCServerCmd `cmd:"" help:"Start the RPC server"`
		Dev       bool                  `help:"Enable dev mode."`
		Version   kong.VersionFlag
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
