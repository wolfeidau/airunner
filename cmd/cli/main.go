package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/wolfeidau/airunner/cmd/cli/internal/commands"
)

var (
	version = "dev"
	cli     struct {
		Worker  commands.WorkerCmd  `cmd:"" help:"Run job worker"`
		Submit  commands.SubmitCmd  `cmd:"" help:"Submit a job"`
		Monitor commands.MonitorCmd `cmd:"" help:"Monitor job events"`
		List    commands.ListCmd    `cmd:"" help:"List jobs"`
		Token   commands.TokenCmd   `cmd:"" help:"Generate a JWT token"`
		Debug   bool                `help:"Enable debug mode."`
		Version kong.VersionFlag
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
