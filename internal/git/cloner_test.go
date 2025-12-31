package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// mockEventPublisher implements EventPublisher for testing
type mockEventPublisher struct {
	events  []*jobv1.JobEvent
	outputs [][]byte
	errors  []error
}

func (m *mockEventPublisher) AddEvent(ctx context.Context, event *jobv1.JobEvent) error {
	m.events = append(m.events, event)
	if len(m.errors) > 0 {
		err := m.errors[0]
		m.errors = m.errors[1:]
		return err
	}
	return nil
}

func (m *mockEventPublisher) AddOutput(ctx context.Context, output []byte, streamType jobv1.StreamType) error {
	m.outputs = append(m.outputs, output)
	if len(m.errors) > 0 {
		err := m.errors[0]
		m.errors = m.errors[1:]
		return err
	}
	return nil
}

func TestNewGitCloner_ValidJobID(t *testing.T) {
	mock := &mockEventPublisher{}
	validJobID := "550e8400-e29b-41d4-a716-446655440000"

	cloner, err := NewGitCloner(mock, validJobID)
	require.NoError(t, err)
	require.NotNil(t, cloner)
	require.Equal(t, mock, cloner.batcher)
	require.Contains(t, cloner.workspace, validJobID)
	require.Contains(t, cloner.workspace, ".airunner/workspaces")
}

func TestNewGitCloner_InvalidJobID(t *testing.T) {
	tests := []struct {
		name  string
		jobID string
	}{
		{
			name:  "empty job ID",
			jobID: "",
		},
		{
			name:  "path traversal with ..",
			jobID: "../../etc/passwd",
		},
		{
			name:  "absolute path",
			jobID: "/etc/passwd",
		},
		{
			name:  "invalid UUID format",
			jobID: "not-a-uuid",
		},
		{
			name:  "UUID without hyphens",
			jobID: "550e8400e29b41d4a716446655440000",
		},
		{
			name:  "uppercase UUID",
			jobID: "550E8400-E29B-41D4-A716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEventPublisher{}
			cloner, err := NewGitCloner(mock, tt.jobID)
			require.Error(t, err)
			require.Nil(t, cloner)
			require.ErrorIs(t, err, ErrInvalidJobID, "expected ErrInvalidJobID, got %v", err)
		})
	}
}

func TestNewGitCloner_WorkspacePathValidation(t *testing.T) {
	mock := &mockEventPublisher{}
	validJobID := "550e8400-e29b-41d4-a716-446655440000"

	cloner, err := NewGitCloner(mock, validJobID)
	require.NoError(t, err)

	// Verify workspace is under $HOME/.airunner/workspaces
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	expectedBase := filepath.Join(homeDir, ".airunner", "workspaces")
	require.True(t, strings.HasPrefix(cloner.workspace, expectedBase),
		"workspace %s should be under %s", cloner.workspace, expectedBase)
}

func TestExtractRepoName(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "github URL with .git",
			url:      "https://github.com/user/repo.git",
			expected: "repo",
		},
		{
			name:     "github URL without .git",
			url:      "https://github.com/user/repo",
			expected: "repo",
		},
		{
			name:     "gitlab URL with .git",
			url:      "https://gitlab.com/user/repo.git",
			expected: "repo",
		},
		{
			name:     "URL with trailing slash",
			url:      "https://github.com/user/repo/",
			expected: "repo",
		},
		{
			name:     "URL with .git and trailing slash",
			url:      "https://github.com/user/repo.git/",
			expected: "repo",
		},
		{
			name:     "URL with query parameters",
			url:      "https://github.com/user/repo.git?ref=main",
			expected: "repo",
		},
		{
			name:     "URL with query parameters and no .git",
			url:      "https://github.com/user/repo?ref=main",
			expected: "repo",
		},
		{
			name:     "empty URL",
			url:      "",
			expected: "unknown-repo",
		},
		{
			name:     "URL with only slashes",
			url:      "///",
			expected: "unknown-repo",
		},
		{
			name:     "nested repo path",
			url:      "https://github.com/org/team/repo.git",
			expected: "repo",
		},
		{
			name:     "repo with dashes",
			url:      "https://github.com/user/my-awesome-repo.git",
			expected: "my-awesome-repo",
		},
		{
			name:     "repo with underscores",
			url:      "https://github.com/user/my_awesome_repo.git",
			expected: "my_awesome_repo",
		},
		{
			name:     "repo with dots in name",
			url:      "https://github.com/user/repo.name.git",
			expected: "repo.name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRepoName(tt.url)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestClone_InvalidURLs(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		branch     string
		commit     string
		wantErr    error
	}{
		{
			name:       "empty repository URL",
			repository: "",
			wantErr:    ErrInvalidGitURL,
		},
		{
			name:       "invalid protocol - file",
			repository: "file:///etc/passwd",
			wantErr:    ErrInvalidGitURL,
		},
		{
			name:       "invalid protocol - ssh",
			repository: "git@github.com:user/repo.git",
			wantErr:    ErrInvalidGitURL,
		},
		{
			name:       "command injection in URL",
			repository: "https://evil.com/repo --upload-pack=/bin/sh",
			wantErr:    ErrInvalidGitURL,
		},
		{
			name:       "valid URL but invalid branch",
			repository: "https://github.com/user/repo.git",
			branch:     "main; rm -rf /",
			wantErr:    ErrInvalidGitRef,
		},
		{
			name:       "valid URL but invalid commit",
			repository: "https://github.com/user/repo.git",
			commit:     "abc123`whoami`",
			wantErr:    ErrInvalidGitRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEventPublisher{}
			validJobID := "550e8400-e29b-41d4-a716-446655440000"

			cloner, err := NewGitCloner(mock, validJobID)
			require.NoError(t, err)

			ctx := context.Background()
			config := &jobv1.GitCloneConfig{
				Enabled: true,
			}
			params := &jobv1.JobParams{
				Repository: tt.repository,
				Branch:     tt.branch,
				Commit:     tt.commit,
			}

			_, err = cloner.Clone(ctx, config, params)
			require.Error(t, err)
			require.ErrorIs(t, err, tt.wantErr,
				"expected error %v, got %v", tt.wantErr, err)
		})
	}
}

func TestCleanup(t *testing.T) {
	mock := &mockEventPublisher{}
	validJobID := "550e8400-e29b-41d4-a716-446655440000"

	cloner, err := NewGitCloner(mock, validJobID)
	require.NoError(t, err)

	// Create the workspace directory
	err = os.MkdirAll(cloner.workspace, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(cloner.workspace) // Cleanup in case test fails

	// Create a test file in workspace
	testFile := filepath.Join(cloner.workspace, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0600)
	require.NoError(t, err)

	// Verify workspace exists
	_, err = os.Stat(cloner.workspace)
	require.NoError(t, err)

	// Cleanup
	err = cloner.Cleanup()
	require.NoError(t, err)

	// Verify workspace is gone
	_, err = os.Stat(cloner.workspace)
	require.True(t, os.IsNotExist(err))
}

func TestCleanup_EmptyWorkspace(t *testing.T) {
	cloner := &GitCloner{
		workspace: "",
	}

	err := cloner.Cleanup()
	require.NoError(t, err)
}

func TestCleanup_NonexistentWorkspace(t *testing.T) {
	cloner := &GitCloner{
		workspace: "/tmp/nonexistent-workspace-12345",
	}

	err := cloner.Cleanup()
	require.NoError(t, err) // Should not error on nonexistent directory
}
