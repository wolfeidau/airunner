// Package git provides Git repository cloning functionality for airunner jobs.
// It supports public repository cloning with configurable depth, branch selection,
// and submodule handling. All git operations are executed in isolated workspace
// directories with automatic cleanup.
//
// Phase 1 implementation supports public repositories only. Authentication for
// private repositories will be added in a future phase.
package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	consolestream "github.com/wolfeidau/console-stream"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventPublisher is an interface for publishing job events and output during
// git clone operations. It allows the cloner to publish progress events and
// git command output to the job's event stream.
type EventPublisher interface {
	AddEvent(ctx context.Context, event *jobv1.JobEvent) error
	AddOutput(ctx context.Context, output []byte, streamType jobv1.StreamType) error
}

// GitCloner handles git repository cloning for airunner jobs. It manages
// workspace creation, git clone execution, ref checkout, and cleanup.
// All operations publish events to the job's event stream for monitoring.
type GitCloner struct {
	batcher   EventPublisher
	workspace string // $HOME/.airunner/workspaces/$jobuuid
}

// NewGitCloner creates a new GitCloner instance for the given job.
// It validates the job ID format and creates an isolated workspace directory.
// Returns an error if the job ID is invalid or workspace cannot be determined.
func NewGitCloner(batcher EventPublisher, jobID string) (*GitCloner, error) {
	// Validate job ID format to prevent path traversal attacks
	if err := validateJobID(jobID); err != nil {
		return nil, fmt.Errorf("invalid job ID: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	workspace := filepath.Join(homeDir, ".airunner", "workspaces", jobID)

	// Verify workspace path is within expected directory (defense in depth)
	expectedBase := filepath.Join(homeDir, ".airunner", "workspaces")
	if !strings.HasPrefix(workspace, expectedBase) {
		return nil, fmt.Errorf("workspace path traversal detected")
	}

	return &GitCloner{
		batcher:   batcher,
		workspace: workspace,
	}, nil
}

func (gc *GitCloner) Clone(ctx context.Context, config *jobv1.GitCloneConfig, params *jobv1.JobParams) (string, error) {
	startTime := time.Now()

	// 1. Validate git repository URL
	if err := validateGitURL(params.Repository); err != nil {
		return "", fmt.Errorf("invalid repository URL: %w", err)
	}

	// 2. Validate branch and commit refs
	if err := validateGitRef(params.Branch); err != nil {
		return "", fmt.Errorf("invalid branch name: %w", err)
	}
	if err := validateGitRef(params.Commit); err != nil {
		return "", fmt.Errorf("invalid commit ref: %w", err)
	}

	// 3. Create workspace directory
	if err := os.MkdirAll(gc.workspace, 0755); err != nil {
		return "", fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// 4. Publish clone start event
	gc.publishCloneStart(params)

	// 5. Build clone destination
	repoName := extractRepoName(params.Repository)
	destDir := filepath.Join(gc.workspace, repoName)

	// 6. Execute git clone (public repos only, no auth)
	if err := gc.executeGitClone(ctx, params, destDir, config); err != nil {
		gc.publishCloneError(err, "")
		return "", err
	}

	// 7. Checkout specific commit if specified
	commitSHA, err := gc.checkoutRef(ctx, destDir, params)
	if err != nil {
		gc.publishCloneError(err, "")
		return "", fmt.Errorf("checkout failed: %w", err)
	}

	// 8. Publish clone end event
	duration := time.Since(startTime)
	gc.publishCloneEnd(commitSHA, duration, destDir)

	log.Info().
		Str("commit_sha", commitSHA).
		Dur("duration", duration).
		Str("dest", destDir).
		Msg("Git clone completed")

	return destDir, nil
}

func (gc *GitCloner) executeGitClone(ctx context.Context, params *jobv1.JobParams, destDir string, config *jobv1.GitCloneConfig) error {
	args := []string{"clone", "--progress"} // --progress forces git to output to stderr

	// Clone options
	if config != nil {
		if config.Depth > 0 {
			args = append(args, "--depth", fmt.Sprintf("%d", config.Depth))
		}
		if config.SingleBranch {
			args = append(args, "--single-branch")
		}
		switch config.Submodules {
		case "recursive":
			args = append(args, "--recurse-submodules")
		case "shallow":
			args = append(args, "--shallow-submodules")
		}
	}

	// Branch
	if params.Branch != "" {
		args = append(args, "--branch", params.Branch)
	}

	args = append(args, params.Repository, destDir)

	// Execute git clone via console-stream for automatic output batching
	// Security: Disable git hooks and global/system config to prevent malicious code execution
	process := consolestream.NewProcess("git", args,
		consolestream.WithPipeMode(),                          // Use pipe mode for git output
		consolestream.WithFlushInterval(100*time.Millisecond), // Fast flushing for git progress
		consolestream.WithEnvMap(map[string]string{
			"GIT_CONFIG_NOGLOBAL": "1", // Ignore global git config
			"GIT_CONFIG_NOSYSTEM": "1", // Ignore system git config
			"GIT_TERMINAL_PROMPT": "0", // Disable credential prompts
		}),
	)

	// Execute and stream events
	var lastError error
	for event, err := range process.ExecuteAndStream(ctx) {
		if err != nil {
			lastError = err
			break
		}

		// Handle output events by forwarding to batcher
		switch e := event.Event.(type) {
		case *consolestream.OutputData:
			// Git progress goes to stderr with --progress flag
			if err := gc.batcher.AddOutput(ctx, e.Data, jobv1.StreamType_STREAM_TYPE_STDERR); err != nil {
				log.Warn().Err(err).Msg("Failed to add git clone output to batcher")
			}
		case *consolestream.ProcessEnd:
			if e.ExitCode != 0 {
				return fmt.Errorf("git clone failed with exit code %d", e.ExitCode)
			}
		}
	}

	if lastError != nil {
		return fmt.Errorf("git clone failed: %w", lastError)
	}

	return nil
}

func (gc *GitCloner) checkoutRef(ctx context.Context, repoDir string, params *jobv1.JobParams) (string, error) {
	// Checkout the requested ref (commit or branch)
	// Note: Refs have already been validated in Clone() method
	if params.Commit != "" {
		// #nosec G204 - git checkout with validated commit SHA
		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "checkout", params.Commit)
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("%w: commit %s: %s", ErrCheckoutFailed, params.Commit, string(output))
		}
	} else if params.Branch != "" {
		// #nosec G204 - git checkout with validated branch name
		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "checkout", params.Branch)
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("%w: branch %s: %s", ErrCheckoutFailed, params.Branch, string(output))
		}
	}

	// Get the actual commit SHA from HEAD
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD commit SHA: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (gc *GitCloner) Cleanup() error {
	if gc.workspace == "" {
		return nil
	}
	log.Info().Str("workspace", gc.workspace).Msg("Cleaning up workspace directory")
	return os.RemoveAll(gc.workspace)
}

// Event publishing methods
func (gc *GitCloner) publishCloneStart(params *jobv1.JobParams) {
	event := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_GIT_CLONE_START,
		EventData: &jobv1.JobEvent_GitCloneStart{
			GitCloneStart: &jobv1.GitCloneStartEvent{
				Repository: params.Repository,
				Commit:     params.Commit,
				Branch:     params.Branch,
				StartedAt:  timestamppb.Now(),
			},
		},
	}
	// Best effort - ignore error
	_ = gc.batcher.AddEvent(context.Background(), event)
}

func (gc *GitCloner) publishCloneEnd(commitSHA string, duration time.Duration, workingDir string) {
	event := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_GIT_CLONE_END,
		EventData: &jobv1.JobEvent_GitCloneEnd{
			GitCloneEnd: &jobv1.GitCloneEndEvent{
				CommitSha:        commitSHA,
				CloneDuration:    durationpb.New(duration),
				WorkingDirectory: workingDir,
			},
		},
	}
	// Best effort - ignore error
	_ = gc.batcher.AddEvent(context.Background(), event)
}

func (gc *GitCloner) publishCloneError(err error, stderr string) {
	event := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_GIT_CLONE_ERROR,
		EventData: &jobv1.JobEvent_GitCloneError{
			GitCloneError: &jobv1.GitCloneErrorEvent{
				ErrorMessage: err.Error(),
				StderrOutput: stderr,
			},
		},
	}
	// Best effort - ignore error
	_ = gc.batcher.AddEvent(context.Background(), event)
}

// Helper functions
func extractRepoName(repoURL string) string {
	// Trim trailing slashes
	repoURL = strings.TrimRight(repoURL, "/")

	// Remove query parameters
	if idx := strings.Index(repoURL, "?"); idx != -1 {
		repoURL = repoURL[:idx]
	}

	parts := strings.Split(repoURL, "/")
	if len(parts) == 0 {
		return "unknown-repo"
	}

	name := parts[len(parts)-1]
	name = strings.TrimSuffix(name, ".git")

	if name == "" {
		return "unknown-repo"
	}

	return name
}
