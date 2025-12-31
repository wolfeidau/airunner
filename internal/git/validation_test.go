package git

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateGitURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errType error
	}{
		// Valid URLs
		{
			name:    "valid https URL",
			url:     "https://github.com/user/repo.git",
			wantErr: false,
		},
		{
			name:    "valid https URL without .git",
			url:     "https://github.com/user/repo",
			wantErr: false,
		},
		{
			name:    "valid git protocol",
			url:     "git://github.com/user/repo.git",
			wantErr: false,
		},
		{
			name:    "valid gitlab URL",
			url:     "https://gitlab.com/user/repo.git",
			wantErr: false,
		},

		// Invalid URLs - empty
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},

		// Invalid URLs - wrong protocol
		{
			name:    "invalid ssh protocol",
			url:     "git@github.com:user/repo.git",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "invalid file protocol",
			url:     "file:///etc/passwd",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "invalid http protocol",
			url:     "http://github.com/user/repo.git",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},

		// Command injection attempts
		{
			name:    "command injection via upload-pack",
			url:     "https://evil.com/repo --upload-pack=/bin/sh",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "command injection via config",
			url:     "https://evil.com/repo --config=core.sshCommand=evil",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with backtick",
			url:     "https://evil.com/repo`whoami`",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with dollar",
			url:     "https://evil.com/repo$USER",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with semicolon",
			url:     "https://evil.com/repo;rm -rf /",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with pipe",
			url:     "https://evil.com/repo | cat /etc/passwd",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with &&",
			url:     "https://evil.com/repo && evil",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
		{
			name:    "shell injection with ||",
			url:     "https://evil.com/repo || evil",
			wantErr: true,
			errType: ErrInvalidGitURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType, "expected error type %v, got %v", tt.errType, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGitRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
		errType error
	}{
		// Valid refs
		{
			name:    "valid branch name",
			ref:     "main",
			wantErr: false,
		},
		{
			name:    "valid branch with slash",
			ref:     "feature/new-feature",
			wantErr: false,
		},
		{
			name:    "valid commit SHA",
			ref:     "abc123def456",
			wantErr: false,
		},
		{
			name:    "valid long commit SHA",
			ref:     "abc123def456789012345678901234567890abcd",
			wantErr: false,
		},
		{
			name:    "valid tag",
			ref:     "v1.0.0",
			wantErr: false,
		},
		{
			name:    "valid tag with dots and dashes",
			ref:     "v1.0.0-rc.1",
			wantErr: false,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: false, // Empty refs are allowed (use default branch)
		},

		// Invalid refs - shell injection
		{
			name:    "invalid shell injection with semicolon",
			ref:     "main; rm -rf /",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid shell injection with backtick",
			ref:     "main`whoami`",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid shell injection with dollar",
			ref:     "main$USER",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid shell injection with pipe",
			ref:     "main | cat",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid shell injection with &&",
			ref:     "main && evil",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},

		// Invalid refs - command-line options
		{
			name:    "invalid option with single dash",
			ref:     "-option",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid option with double dash",
			ref:     "--option=value",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},

		// Invalid refs - special characters
		{
			name:    "invalid ref with parentheses",
			ref:     "branch(test)",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid ref with space",
			ref:     "main branch",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
		{
			name:    "invalid ref with equals",
			ref:     "branch=value",
			wantErr: true,
			errType: ErrInvalidGitRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGitRef(tt.ref)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType, "expected error type %v, got %v", tt.errType, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateJobID(t *testing.T) {
	tests := []struct {
		name    string
		jobID   string
		wantErr bool
		errType error
	}{
		// Valid job IDs
		{
			name:    "valid UUID v4",
			jobID:   "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid UUID lowercase",
			jobID:   "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantErr: false,
		},

		// Invalid job IDs
		{
			name:    "empty job ID",
			jobID:   "",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "invalid UUID format - missing hyphens",
			jobID:   "550e8400e29b41d4a716446655440000",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "invalid UUID format - wrong positions",
			jobID:   "550e8400-e29b41d4-a716-446655440000",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "path traversal attempt with ..",
			jobID:   "../../etc/passwd",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "path traversal attempt with absolute path",
			jobID:   "/etc/passwd",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "invalid uppercase UUID",
			jobID:   "550E8400-E29B-41D4-A716-446655440000",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "invalid characters",
			jobID:   "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "too short",
			jobID:   "550e8400-e29b-41d4-a716",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
		{
			name:    "too long",
			jobID:   "550e8400-e29b-41d4-a716-446655440000-extra",
			wantErr: true,
			errType: ErrInvalidJobID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJobID(tt.jobID)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType, "expected error type %v, got %v", tt.errType, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
