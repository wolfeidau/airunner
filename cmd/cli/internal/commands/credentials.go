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
			return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials", c.Name)
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
			return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials", c.Name)
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
		_, _ = fmt.Scanln(&response)
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
			return fmt.Errorf("credential %q not found\n\nRun 'airunner-cli credentials list' to see available credentials", c.Name)
		}
		return fmt.Errorf("failed to get credential: %w", err)
	}

	if err := store.SetDefault(c.Name); err != nil {
		return fmt.Errorf("failed to set default: %w", err)
	}

	fmt.Printf("Default credential set to %q.\n", c.Name)
	return nil
}
