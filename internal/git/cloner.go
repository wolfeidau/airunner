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

// EventPublisher is an interface for publishing job events and output
type EventPublisher interface {
	AddEvent(ctx context.Context, event *jobv1.JobEvent) error
	AddOutput(ctx context.Context, output []byte, streamType jobv1.StreamType) error
}

type GitCloner struct {
	batcher   EventPublisher
	workspace string // $HOME/.airunner/workspaces/$jobuuid
}

func NewGitCloner(batcher EventPublisher, jobID string) *GitCloner {
	homeDir, _ := os.UserHomeDir()
	workspace := filepath.Join(homeDir, ".airunner", "workspaces", jobID)

	return &GitCloner{
		batcher:   batcher,
		workspace: workspace,
	}
}

func (gc *GitCloner) Clone(ctx context.Context, config *jobv1.GitCloneConfig, params *jobv1.JobParams) (string, error) {
	startTime := time.Now()

	// 1. Create workspace directory
	if err := os.MkdirAll(gc.workspace, 0755); err != nil {
		return "", fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// 2. Publish clone start event
	gc.publishCloneStart(params)

	// 3. Build clone destination
	repoName := extractRepoName(params.Repository)
	destDir := filepath.Join(gc.workspace, repoName)

	// 4. Execute git clone (public repos only, no auth)
	if err := gc.executeGitClone(ctx, params, destDir, config); err != nil {
		gc.publishCloneError(err, "")
		return "", err
	}

	// 5. Checkout specific commit if specified
	commitSHA := gc.checkoutRef(ctx, destDir, params)

	// 6. Publish clone end event
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
	process := consolestream.NewProcess("git", args,
		consolestream.WithPipeMode(),                          // Use pipe mode for git output
		consolestream.WithFlushInterval(100*time.Millisecond), // Fast flushing for git progress
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
			// Send git output through batcher (best effort)
			_ = gc.batcher.AddOutput(ctx, e.Data, 0)
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

func (gc *GitCloner) checkoutRef(ctx context.Context, repoDir string, params *jobv1.JobParams) string {
	// Checkout the requested ref (commit or branch)
	if params.Commit != "" {
		// #nosec G204 - git checkout with user-provided commit SHA is expected behavior
		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "checkout", params.Commit)
		_ = cmd.Run() // Best effort - ignore error
	} else if params.Branch != "" {
		// #nosec G204 - git checkout with user-provided branch is expected behavior
		cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "checkout", params.Branch)
		_ = cmd.Run() // Best effort - ignore error
	}

	// Always get the actual commit SHA from HEAD (even if checkout failed, we want the current SHA)
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
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
	parts := strings.Split(repoURL, "/")
	name := parts[len(parts)-1]
	return strings.TrimSuffix(name, ".git")
}
