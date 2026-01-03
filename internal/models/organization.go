package models

import (
	"time"

	"github.com/google/uuid"
)

// Organization represents an organization (tenant) in the system.
// Each organization can have multiple principals (users, workers, services).
type Organization struct {
	OrgID            uuid.UUID // UUIDv7
	Name             string
	OwnerPrincipalID uuid.UUID // UUIDv7, FK to principals
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
