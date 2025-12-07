package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/wolfeidau/airunner/internal/auth"
)

type TokenCmd struct {
	Subject    string        `help:"Subject identifier" required:""`
	TTL        time.Duration `help:"Token lifetime" default:"1h"`
	SigningKey string        `help:"JWT signing key" required:"" env:"JWT_SIGNING_KEY"`
}

func (t *TokenCmd) Run(ctx context.Context) error {

	token, err := auth.IssueToken(t.SigningKey, t.Subject, t.TTL)
	if err != nil {
		return err
	}

	fmt.Println(token)
	return nil
}
