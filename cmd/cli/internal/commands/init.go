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

	// Set as default if requested
	if c.SetDefault {
		if err := store.SetDefault(c.Name); err != nil {
			return fmt.Errorf("failed to set default: %w", err)
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
