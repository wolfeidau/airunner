package commands

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

type testCLI struct {
	Debug   bool       `help:"Enable debug mode."`
	Server  ServerCmd  `cmd:""`
	Cleanup CleanupCmd `cmd:""`
}

func newTestParser(t *testing.T, cli *testCLI) *kong.Kong {
	t.Helper()
	// PostgresStoreFlags.Validate runs during Parse; set placeholders so the tests do not
	// depend on the developer's environment (CI has neither variable).
	t.Setenv("POSTGRES_CONNECTION_STRING", "postgres://test@localhost/test")
	t.Setenv("AIRUNNER_POSTGRES_TOKEN_SECRET", "test-secret-key-min-32-bytes-long")
	parser, err := kong.New(cli)
	require.NoError(t, err)
	return parser
}

func TestCleanupRejectsAutoMigrate(t *testing.T) {
	var cli testCLI
	parser := newTestParser(t, &cli)

	_, err := parser.Parse([]string{"cleanup", "--postgres-auto-migrate"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown flag")
	require.Contains(t, err.Error(), "postgres-auto-migrate")
}

func TestServerAcceptsAutoMigrate(t *testing.T) {
	var cli testCLI
	parser := newTestParser(t, &cli)

	_, err := parser.Parse([]string{"server", "--postgres-auto-migrate"})
	require.NoError(t, err)
	require.True(t, cli.Server.AutoMigrate)

	var cli2 testCLI
	parser = newTestParser(t, &cli2)
	_, err = parser.Parse([]string{"server"})
	require.NoError(t, err)
	require.False(t, cli2.Server.AutoMigrate)
}

func TestAutoMigrateFlagListedForServerOnly(t *testing.T) {
	var cli testCLI
	parser := newTestParser(t, &cli)

	flagNames := func(cmd string) []string {
		for _, n := range parser.Model.Children {
			if n.Name == cmd {
				var names []string
				for _, f := range n.Flags {
					names = append(names, f.Name)
				}
				return names
			}
		}
		t.Fatalf("command %q not found", cmd)
		return nil
	}
	require.Contains(t, flagNames("server"), "postgres-auto-migrate")
	require.NotContains(t, flagNames("cleanup"), "postgres-auto-migrate")
}

func TestValidateNamesSigningSecretFlag(t *testing.T) {
	f := PostgresStoreFlags{ConnString: "postgres://x"}
	err := f.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "--postgres-token-signing-secret")
}
