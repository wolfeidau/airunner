package main

import (
	"context"

	"github.com/alecthomas/kong"
	"github.com/wolfeidau/airunner/cmd/cli/internal/commands"
)

var (
	version = "dev"
	cli     struct {
		Worker      commands.WorkerCmd      `cmd:"" help:"Run job worker"`
		Submit      commands.SubmitCmd      `cmd:"" help:"Submit a job"`
		Monitor     commands.MonitorCmd     `cmd:"" help:"Monitor job events"`
		Cancel      commands.CancelCmd      `cmd:"" help:"Cancel a scheduled or running job"`
		List        commands.ListCmd        `cmd:"" help:"List jobs"`
		Init        commands.InitCmd        `cmd:"" help:"Initialize a new credential"`
		Credentials commands.CredentialsCmd `cmd:"" help:"Manage credentials"`
		TestOutput  commands.TestOutputCmd  `cmd:"" help:"Generate test output with known timing patterns"`
		TestStatus  commands.TestStatusCmd  `cmd:"" help:"Emit OSC 7501 program status reports for demos and testing"`
		Debug       bool                    `help:"Enable debug mode."`
		Version     kong.VersionFlag
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
