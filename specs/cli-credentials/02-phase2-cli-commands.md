# Phase 2: CLI Commands

[← README](README.md) | [← Phase 1: Local Storage](01-phase1-local-storage.md) | [Phase 3: JWT Signing →](03-phase3-jwt-signing.md)

## Goal

Implement the `init` and `credentials` CLI commands using the Kong CLI framework.

## Prerequisites

- [Phase 1: Local Storage](01-phase1-local-storage.md) completed
- `cmd/cli/internal/credentials/store.go` implemented

## Success Criteria

- [ ] `airunner-cli init <name>` generates keypair and displays public key
- [ ] `airunner-cli init <name> --set-default` sets as default credential
- [ ] `airunner-cli credentials list` shows all credentials with status
- [ ] `airunner-cli credentials show <name>` displays full details
- [ ] `airunner-cli credentials update <name> --org-id --principal-id` marks as imported
- [ ] `airunner-cli credentials delete <name>` removes credential
- [ ] `airunner-cli credentials set-default <name>` changes default
- [ ] Clear error messages for all failure modes

## Files to Create

1. `cmd/cli/internal/commands/init.go` - Init command
2. `cmd/cli/internal/commands/credentials.go` - Credentials subcommands

## Update main.go

Add the new commands to the CLI struct:

```go
// cmd/cli/main.go
var (
    cli struct {
        Worker      commands.WorkerCmd      `cmd:"" help:"Run job worker"`
        Submit      commands.SubmitCmd      `cmd:"" help:"Submit a job"`
        Monitor     commands.MonitorCmd     `cmd:"" help:"Monitor job events"`
        List        commands.ListCmd        `cmd:"" help:"List jobs"`
        Init        commands.InitCmd        `cmd:"" help:"Initialize a new credential"`
        Credentials commands.CredentialsCmd `cmd:"" help:"Manage credentials"`
        TestOutput  commands.TestOutputCmd  `cmd:"" help:"Generate test output with known timing patterns"`
        Debug       bool                    `help:"Enable debug mode."`
        Version     kong.VersionFlag
    }
)
```

## Init Command

`cmd/cli/internal/commands/init.go`:

```go
package commands

import (
    "context"
    "fmt"

    "github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
)

// InitCmd generates a new credential keypair.
type InitCmd struct {
    Name       string `arg:"" help:"Name for the credential (e.g., production-workers)"`
    SetDefault bool   `help:"Set as the default credential" default:"false"`
    OutputDir  string `help:"Custom credentials directory (default: ~/.airunner/credentials/)"`
}

func (c *InitCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    // Create the credential
    cred, err := store.Create(c.Name)
    if err != nil {
        if err == credentials.ErrCredentialExists {
            return fmt.Errorf("credential %q already exists\n\nTo delete and recreate:\n  airunner-cli credentials delete %s\n  airunner-cli init %s", c.Name, c.Name, c.Name)
        }
        return fmt.Errorf("failed to create credential: %w", err)
    }

    // Set as default if requested or if it's the first credential
    if c.SetDefault {
        if err := store.SetDefault(c.Name); err != nil {
            return fmt.Errorf("failed to set default: %w", err)
        }
    } else {
        // Auto-set as default if it's the only credential
        creds, _ := store.List()
        if len(creds) == 1 {
            _ = store.SetDefault(c.Name)
        }
    }

    // Load public key for display
    publicKeyPEM, err := store.LoadPublicKeyPEM(c.Name)
    if err != nil {
        return fmt.Errorf("failed to load public key: %w", err)
    }

    // Display result
    fmt.Printf("Generated credential: %s\n", cred.Name)
    fmt.Printf("Fingerprint: %s\n", cred.Fingerprint)
    fmt.Println()
    fmt.Println("NOT IMPORTED YET - cannot use for API authentication")
    fmt.Println()
    fmt.Println("To import via web UI:")
    fmt.Println("  1. Copy the public key below")
    fmt.Println("  2. Log into web UI (GitHub OAuth)")
    fmt.Println("  3. Import credential and note the org_id and principal_id")
    fmt.Printf("  4. Run: airunner-cli credentials update %s --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>\n", c.Name)
    fmt.Println()
    fmt.Println("Public Key (copy this):")
    fmt.Println(publicKeyPEM)

    return nil
}
```

## Credentials Command

`cmd/cli/internal/commands/credentials.go`:

```go
package commands

import (
    "context"
    "fmt"
    "os"
    "text/tabwriter"

    "github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
)

// CredentialsCmd manages local credentials.
type CredentialsCmd struct {
    List       CredentialsListCmd       `cmd:"" help:"List all credentials"`
    Show       CredentialsShowCmd       `cmd:"" help:"Show credential details"`
    Update     CredentialsUpdateCmd     `cmd:"" help:"Update credential after import"`
    Delete     CredentialsDeleteCmd     `cmd:"" help:"Delete a credential"`
    SetDefault CredentialsSetDefaultCmd `cmd:"" name:"set-default" help:"Set the default credential"`
}

// CredentialsListCmd lists all credentials.
type CredentialsListCmd struct {
    OutputDir string `help:"Custom credentials directory"`
}

func (c *CredentialsListCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    creds, err := store.List()
    if err != nil {
        return fmt.Errorf("failed to list credentials: %w", err)
    }

    if len(creds) == 0 {
        fmt.Println("No credentials found.")
        fmt.Println()
        fmt.Println("To create a new credential:")
        fmt.Println("  airunner-cli init <name>")
        return nil
    }

    // Get default credential
    defaultCred, _ := store.GetDefault()
    defaultName := ""
    if defaultCred != nil {
        defaultName = defaultCred.Name
    }

    // Print as table
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    fmt.Fprintln(w, "NAME\tSTATUS\tFINGERPRINT\tDEFAULT")

    for _, cred := range creds {
        status := "not imported"
        if cred.IsImported() {
            status = "imported"
        }

        isDefault := ""
        if cred.Name == defaultName {
            isDefault = "*"
        }

        // Truncate fingerprint for display
        fp := cred.Fingerprint
        if len(fp) > 12 {
            fp = fp[:12] + "..."
        }

        fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", cred.Name, status, fp, isDefault)
    }

    w.Flush()
    return nil
}

// CredentialsShowCmd shows details of a credential.
type CredentialsShowCmd struct {
    Name      string `arg:"" help:"Credential name"`
    OutputDir string `help:"Custom credentials directory"`
}

func (c *CredentialsShowCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    cred, err := store.Get(c.Name)
    if err != nil {
        if err == credentials.ErrCredentialNotFound {
            return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials.", c.Name)
        }
        return fmt.Errorf("failed to get credential: %w", err)
    }

    publicKeyPEM, err := store.LoadPublicKeyPEM(c.Name)
    if err != nil {
        return fmt.Errorf("failed to load public key: %w", err)
    }

    fmt.Printf("Name:         %s\n", cred.Name)
    fmt.Printf("Fingerprint:  %s\n", cred.Fingerprint)
    fmt.Printf("Imported:     %v\n", cred.IsImported())

    if cred.OrgID != "" {
        fmt.Printf("Org ID:       %s\n", cred.OrgID)
    }
    if cred.PrincipalID != "" {
        fmt.Printf("Principal ID: %s\n", cred.PrincipalID)
    }

    fmt.Printf("Created:      %s\n", cred.CreatedAt.Format("2006-01-02 15:04:05"))
    fmt.Printf("Updated:      %s\n", cred.UpdatedAt.Format("2006-01-02 15:04:05"))
    fmt.Println()
    fmt.Println("Public Key:")
    fmt.Println(publicKeyPEM)

    return nil
}

// CredentialsUpdateCmd updates credential after server import.
type CredentialsUpdateCmd struct {
    Name        string `arg:"" help:"Credential name"`
    OrgID       string `help:"Organization ID from server" required:""`
    PrincipalID string `help:"Principal ID from server" required:""`
    OutputDir   string `help:"Custom credentials directory"`
}

func (c *CredentialsUpdateCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    // Verify credential exists
    _, err = store.Get(c.Name)
    if err != nil {
        if err == credentials.ErrCredentialNotFound {
            return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials.", c.Name)
        }
        return fmt.Errorf("failed to get credential: %w", err)
    }

    // Update with server IDs
    if err := store.Update(c.Name, c.OrgID, c.PrincipalID); err != nil {
        return fmt.Errorf("failed to update credential: %w", err)
    }

    fmt.Printf("Credential %q updated successfully.\n", c.Name)
    fmt.Println()
    fmt.Println("You can now use this credential for API authentication:")
    fmt.Printf("  airunner-cli worker --credential %s\n", c.Name)
    fmt.Printf("  airunner-cli submit --credential %s ...\n", c.Name)

    return nil
}

// CredentialsDeleteCmd deletes a credential.
type CredentialsDeleteCmd struct {
    Name      string `arg:"" help:"Credential name"`
    Force     bool   `help:"Skip confirmation" default:"false"`
    OutputDir string `help:"Custom credentials directory"`
}

func (c *CredentialsDeleteCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    // Verify credential exists
    cred, err := store.Get(c.Name)
    if err != nil {
        if err == credentials.ErrCredentialNotFound {
            return fmt.Errorf("credential %q not found", c.Name)
        }
        return fmt.Errorf("failed to get credential: %w", err)
    }

    // Warn if imported
    if !c.Force && cred.IsImported() {
        fmt.Printf("Warning: Credential %q is imported and may be in use.\n", c.Name)
        fmt.Println("Deleting will not revoke the credential on the server.")
        fmt.Println()
        fmt.Print("Continue? [y/N]: ")

        var response string
        fmt.Scanln(&response)
        if response != "y" && response != "Y" {
            fmt.Println("Aborted.")
            return nil
        }
    }

    if err := store.Delete(c.Name); err != nil {
        return fmt.Errorf("failed to delete credential: %w", err)
    }

    fmt.Printf("Credential %q deleted.\n", c.Name)

    if cred.IsImported() {
        fmt.Println()
        fmt.Println("Note: To fully revoke this credential, use the web UI to revoke it on the server.")
    }

    return nil
}

// CredentialsSetDefaultCmd sets the default credential.
type CredentialsSetDefaultCmd struct {
    Name      string `arg:"" help:"Credential name"`
    OutputDir string `help:"Custom credentials directory"`
}

func (c *CredentialsSetDefaultCmd) Run(ctx context.Context, globals *Globals) error {
    store, err := credentials.NewStore(c.OutputDir)
    if err != nil {
        return fmt.Errorf("failed to initialize credential store: %w", err)
    }

    // Verify credential exists
    if _, err := store.Get(c.Name); err != nil {
        if err == credentials.ErrCredentialNotFound {
            return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials.", c.Name)
        }
        return fmt.Errorf("failed to get credential: %w", err)
    }

    if err := store.SetDefault(c.Name); err != nil {
        return fmt.Errorf("failed to set default: %w", err)
    }

    fmt.Printf("Default credential set to %q.\n", c.Name)
    return nil
}
```

## Example Usage

```bash
# Generate new credential
$ airunner-cli init production-workers
Generated credential: production-workers
Fingerprint: 7RpMx9NqK4vBwE8mJdHnLpQrYtUzXcAf2sGiW6hN3oS

NOT IMPORTED YET - cannot use for API authentication

To import via web UI:
  1. Copy the public key below
  2. Log into web UI (GitHub OAuth)
  3. Import credential and note the org_id and principal_id
  4. Run: airunner-cli credentials update production-workers --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>

Public Key (copy this):
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----

# List credentials
$ airunner-cli credentials list
NAME                STATUS        FINGERPRINT       DEFAULT
production-workers  not imported  7RpMx9NqK4vB...   *
staging-workers     imported      3KpLm8NqR5vC...

# Update after web import
$ airunner-cli credentials update production-workers \
    --org-id 018f1234-5678-7abc-def0-abcdef123456 \
    --principal-id 018f5678-90ab-cdef-1234-567890abcdef
Credential "production-workers" updated successfully.

You can now use this credential for API authentication:
  airunner-cli worker --credential production-workers
  airunner-cli submit --credential production-workers ...

# Show credential details
$ airunner-cli credentials show production-workers
Name:         production-workers
Fingerprint:  7RpMx9NqK4vBwE8mJdHnLpQrYtUzXcAf2sGiW6hN3oS
Imported:     true
Org ID:       018f1234-5678-7abc-def0-abcdef123456
Principal ID: 018f5678-90ab-cdef-1234-567890abcdef
Created:      2024-01-15 10:30:00
Updated:      2024-01-15 11:00:00

Public Key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----

# Change default
$ airunner-cli credentials set-default staging-workers
Default credential set to "staging-workers".

# Delete credential
$ airunner-cli credentials delete staging-workers
Warning: Credential "staging-workers" is imported and may be in use.
Deleting will not revoke the credential on the server.

Continue? [y/N]: y
Credential "staging-workers" deleted.

Note: To fully revoke this credential, use the web UI to revoke it on the server.
```

## Testing

Create `cmd/cli/internal/commands/init_test.go`:

```go
func TestInitCmd_Run(t *testing.T) {
    tmpDir := t.TempDir()

    cmd := &InitCmd{
        Name:      "test-workers",
        OutputDir: tmpDir,
    }

    err := cmd.Run(context.Background(), &Globals{})
    require.NoError(t, err)

    // Verify files created
    _, err = os.Stat(filepath.Join(tmpDir, "test-workers.key"))
    assert.NoError(t, err)
    _, err = os.Stat(filepath.Join(tmpDir, "test-workers.pub"))
    assert.NoError(t, err)
}

func TestInitCmd_Duplicate(t *testing.T) {
    tmpDir := t.TempDir()

    cmd := &InitCmd{
        Name:      "test-workers",
        OutputDir: tmpDir,
    }

    err := cmd.Run(context.Background(), &Globals{})
    require.NoError(t, err)

    // Try to create duplicate
    err = cmd.Run(context.Background(), &Globals{})
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "already exists")
}
```

Create `cmd/cli/internal/commands/credentials_test.go`:

```go
func TestCredentialsListCmd_Empty(t *testing.T) {
    tmpDir := t.TempDir()

    cmd := &CredentialsListCmd{OutputDir: tmpDir}
    err := cmd.Run(context.Background(), &Globals{})
    require.NoError(t, err)
}

func TestCredentialsUpdateCmd_NotFound(t *testing.T) {
    tmpDir := t.TempDir()

    cmd := &CredentialsUpdateCmd{
        Name:        "nonexistent",
        OrgID:       "org-123",
        PrincipalID: "principal-456",
        OutputDir:   tmpDir,
    }

    err := cmd.Run(context.Background(), &Globals{})
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "not found")
}
```

## Verification

After implementing:

```bash
# Build CLI
make build-cli

# Test init
./bin/airunner-cli init test-cred

# Test list
./bin/airunner-cli credentials list

# Test show
./bin/airunner-cli credentials show test-cred

# Test update (with fake IDs)
./bin/airunner-cli credentials update test-cred \
  --org-id 018f1234-5678-7abc-def0-abcdef123456 \
  --principal-id 018f5678-90ab-cdef-1234-567890abcdef

# Test set-default
./bin/airunner-cli credentials set-default test-cred

# Test delete
./bin/airunner-cli credentials delete test-cred --force

# Run tests
go test ./cmd/cli/internal/commands/...
```

---

[← README](README.md) | [← Phase 1: Local Storage](01-phase1-local-storage.md) | [Phase 3: JWT Signing →](03-phase3-jwt-signing.md)
