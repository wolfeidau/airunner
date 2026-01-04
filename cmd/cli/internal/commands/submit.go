package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/google/uuid"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
	"github.com/wolfeidau/airunner/internal/client"
	"gopkg.in/yaml.v3"
)

type ContainerMountConfig struct {
	Source   string `yaml:"source" json:"source"`
	Target   string `yaml:"target" json:"target"`
	ReadOnly bool   `yaml:"readOnly" json:"readOnly"`
}

type JobConfig struct {
	Command          string            `yaml:"command" json:"command"`
	Args             []string          `yaml:"args" json:"args"`
	ProcessType      string            `yaml:"processType" json:"processType"`
	TimeoutSeconds   int               `yaml:"timeout" json:"timeout"`
	WorkingDirectory string            `yaml:"workingDirectory" json:"workingDirectory"`
	Environment      map[string]string `yaml:"environment" json:"environment"`
	Metadata         map[string]string `yaml:"metadata" json:"metadata"`
	Repository       string            `yaml:"repository" json:"repository"`
	Commit           string            `yaml:"commit" json:"commit"`
	Branch           string            `yaml:"branch" json:"branch"`
	Owner            string            `yaml:"owner" json:"owner"`

	// Container configuration
	ContainerEnabled bool                   `yaml:"containerEnabled" json:"containerEnabled"`
	ContainerImage   string                 `yaml:"containerImage" json:"containerImage"`
	ContainerRuntime string                 `yaml:"containerRuntime" json:"containerRuntime"`
	ContainerMounts  []ContainerMountConfig `yaml:"containerMounts" json:"containerMounts"`

	// Git clone configuration (Phase 1: Public repos only)
	GitCloneEnabled      bool   `yaml:"gitCloneEnabled" json:"gitCloneEnabled"`
	GitCloneDepth        int32  `yaml:"gitCloneDepth" json:"gitCloneDepth"`
	GitCloneSingleBranch bool   `yaml:"gitCloneSingleBranch" json:"gitCloneSingleBranch"`
	GitCloneSubmodules   string `yaml:"gitCloneSubmodules" json:"gitCloneSubmodules"`
}

type SubmitCmd struct {
	Server           string            `help:"Server URL" default:"https://localhost"`
	Queue            string            `help:"Queue name" default:"default"`
	Credential       string            `help:"Credential name (uses default if not specified)"`
	Repository       string            `arg:"" help:"Repository URL to process"`
	Commit           string            `help:"Commit hash or identifier (takes precedence over branch if specified)"`
	Branch           string            `help:"Branch name" default:"main"`
	Owner            string            `help:"Job owner" default:""`
	Env              map[string]string `help:"Environment variables"`
	Metadata         map[string]string `help:"Additional metadata"`
	Monitor          bool              `help:"Monitor job after submission" default:"true"`
	Command          string            `help:"Command to execute"`
	Args             []string          `help:"Command arguments"`
	ProcessType      string            `help:"Process type: pipe or pty" default:"pty"`
	TimeoutSeconds   int               `help:"Command timeout in seconds" default:"300"`
	WorkingDirectory string            `help:"Working directory for command execution"`
	Config           string            `help:"YAML/JSON config file path"`
	Timeout          time.Duration     `help:"Timeout for the monitor" default:"5m"`

	// Container flags
	ContainerEnabled bool     `help:"Run job in a container"`
	ContainerImage   string   `help:"Container image (e.g., golang:1.21)"`
	ContainerRuntime string   `help:"Container runtime: docker or podman" default:"docker"`
	ContainerMounts  []string `help:"Volume mounts (format: src:dst or src:dst:ro)"`

	// Git clone flags (Phase 1: Public repos only)
	GitCloneEnabled      bool   `help:"Clone repository before execution (public repos only)"`
	GitCloneDepth        int32  `help:"Clone depth (0 = full clone, 1 = shallow)"`
	GitCloneSingleBranch bool   `help:"Only clone the specified branch"`
	GitCloneSubmodules   string `help:"Submodule handling: recursive, shallow, or empty"`
}

func (s *SubmitCmd) Run(ctx context.Context, globals *Globals) error {
	// Load config from file if provided
	if s.Config != "" {
		if err := s.loadConfigFile(); err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Validate that command is specified
	if s.Command == "" {
		return fmt.Errorf("command is required (use --command flag or --config file)")
	}

	fmt.Printf("Submitting job for repository %s to server %s\n", s.Repository, s.Server)

	// Initialize credential store and auth interceptor
	store, err := credentials.NewStore("")
	if err != nil {
		return fmt.Errorf("failed to initialize credentials: %w", err)
	}

	authInterceptor, err := credentials.NewAuthInterceptor(store, s.Credential, s.Server)
	if err != nil {
		return err
	}

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	// Create clients
	config := client.Config{
		ServerURL: s.Server,
		Timeout:   s.Timeout,
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config,
		connect.WithInterceptors(authInterceptor),
		connect.WithInterceptors(otelInterceptor),
	)
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

	// Submit job
	jobID, err := s.submitJob(ctx, clients)
	if err != nil {
		return fmt.Errorf("failed to submit job: %w", err)
	}

	fmt.Printf("Job submitted successfully with ID: %s\n", jobID)

	if s.Monitor {
		if err := monitorJob(ctx, clients, monitorJobArgs{
			JobID:         jobID,
			FromSequence:  0,
			FromTimestamp: 0,
			EventFilter:   nil,
		}); err != nil {
			return fmt.Errorf("failed to monitor job: %w", err)
		}
	}

	return nil
}

func (s *SubmitCmd) loadConfigFile() error {
	data, err := os.ReadFile(s.Config)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config JobConfig

	// Determine file format by extension
	if strings.HasSuffix(strings.ToLower(s.Config), ".json") {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	} else {
		// Default to YAML
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	}

	// Override struct fields with config values (config file takes precedence over flags)
	if config.Command != "" {
		s.Command = config.Command
	}
	if len(config.Args) > 0 {
		s.Args = config.Args
	}
	if config.ProcessType != "" {
		s.ProcessType = config.ProcessType
	}
	if config.TimeoutSeconds > 0 {
		s.TimeoutSeconds = config.TimeoutSeconds
	}
	if config.WorkingDirectory != "" {
		s.WorkingDirectory = config.WorkingDirectory
	}
	if config.Repository != "" {
		s.Repository = config.Repository
	}
	if config.Commit != "" {
		s.Commit = config.Commit
	}
	if config.Branch != "" {
		s.Branch = config.Branch
	}
	if config.Owner != "" {
		s.Owner = config.Owner
	}
	if len(config.Environment) > 0 {
		if s.Env == nil {
			s.Env = make(map[string]string)
		}
		for k, v := range config.Environment {
			s.Env[k] = v
		}
	}
	if len(config.Metadata) > 0 {
		if s.Metadata == nil {
			s.Metadata = make(map[string]string)
		}
		for k, v := range config.Metadata {
			s.Metadata[k] = v
		}
	}

	// Container configuration
	if config.ContainerEnabled {
		s.ContainerEnabled = config.ContainerEnabled
	}
	if config.ContainerImage != "" {
		s.ContainerImage = config.ContainerImage
	}
	if config.ContainerRuntime != "" {
		s.ContainerRuntime = config.ContainerRuntime
	}
	if len(config.ContainerMounts) > 0 {
		for _, mount := range config.ContainerMounts {
			mountStr := mount.Source + ":" + mount.Target
			if mount.ReadOnly {
				mountStr += ":ro"
			}
			s.ContainerMounts = append(s.ContainerMounts, mountStr)
		}
	}

	// Git clone configuration
	if config.GitCloneEnabled {
		s.GitCloneEnabled = config.GitCloneEnabled
	}
	if config.GitCloneDepth > 0 {
		s.GitCloneDepth = config.GitCloneDepth
	}
	if config.GitCloneSingleBranch {
		s.GitCloneSingleBranch = config.GitCloneSingleBranch
	}
	if config.GitCloneSubmodules != "" {
		s.GitCloneSubmodules = config.GitCloneSubmodules
	}

	return nil
}

func (s *SubmitCmd) submitJob(ctx context.Context, clients *client.Clients) (string, error) {
	// Set default environment if none provided
	env := s.Env
	if env == nil {
		env = map[string]string{
			"BUILD_TYPE": "release",
			"NODE_ENV":   "production",
		}
	}

	// Set default metadata if none provided
	metadata := s.Metadata
	if metadata == nil {
		metadata = map[string]string{
			"submitter": "airunner-agent",
			"priority":  "normal",
		}
	}

	// Set default owner if not provided
	owner := s.Owner
	if owner == "" {
		owner = "airunner-user"
	}

	// Convert process type string to enum
	var processType jobv1.ProcessType
	switch strings.ToLower(s.ProcessType) {
	case "pipe":
		processType = jobv1.ProcessType_PROCESS_TYPE_PIPE
	case "pty":
		processType = jobv1.ProcessType_PROCESS_TYPE_PTY
	default:
		processType = jobv1.ProcessType_PROCESS_TYPE_PTY // Default to PTY
	}

	// Build container config
	var containerConfig *jobv1.ContainerConfig
	if s.ContainerEnabled {
		containerConfig = &jobv1.ContainerConfig{
			Enabled: true,
			Image:   s.ContainerImage,
			Runtime: s.ContainerRuntime,
		}

		// Parse and validate volume mounts
		for _, mountStr := range s.ContainerMounts {
			mount, err := parseMount(mountStr)
			if err != nil {
				return "", fmt.Errorf("invalid mount configuration: %w", err)
			}
			containerConfig.Mounts = append(containerConfig.Mounts, mount)
		}
	}

	// Build git clone config (Phase 1: Public repos only, no auth)
	var gitCloneConfig *jobv1.GitCloneConfig
	if s.GitCloneEnabled {
		gitCloneConfig = &jobv1.GitCloneConfig{
			Enabled:      true,
			Depth:        s.GitCloneDepth,
			SingleBranch: s.GitCloneSingleBranch,
			Submodules:   s.GitCloneSubmodules,
		}
	}

	req := &jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(), // Idempotency token
		Queue:     s.Queue,
		JobParams: &jobv1.JobParams{
			Repository:  s.Repository,
			Commit:      s.Commit,
			Branch:      s.Branch,
			Environment: env,
			Metadata:    metadata,
			Owner:       owner,
			Command:     s.Command,
			Args:        s.Args,
			ProcessType: processType,
			TimeoutSeconds: func() int32 {
				if s.TimeoutSeconds > 2147483647 {
					return 2147483647
				}
				if s.TimeoutSeconds < 0 {
					return 0
				}
				// #nosec G115 - bounded by explicit check
				return int32(s.TimeoutSeconds)
			}(),
			WorkingDirectory: s.WorkingDirectory,
			Container:        containerConfig,
			GitClone:         gitCloneConfig,
		},
	}

	resp, err := clients.Job.EnqueueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return "", fmt.Errorf("failed to enqueue job: %w", err)
	}

	return resp.Msg.JobId, nil
}

// parseMount parses and validates volume mount format: src:dst or src:dst:ro
// Source paths must be absolute and under $HOME/.airunner for security
// Target paths cannot be mounted to dangerous container paths
func parseMount(mountStr string) (*jobv1.ContainerMount, error) {
	parts := strings.Split(mountStr, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid mount format: %s (expected src:dst or src:dst:ro)", mountStr)
	}

	source := parts[0]
	target := parts[1]

	// Validate source is absolute path
	if !filepath.IsAbs(source) {
		return nil, fmt.Errorf("mount source must be absolute path: %s", source)
	}

	// Validate source is under $HOME/.airunner
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	airunnerBase := filepath.Join(homeDir, ".airunner")
	// Clean the paths to handle .. and . properly
	cleanSource := filepath.Clean(source)
	if !strings.HasPrefix(cleanSource, airunnerBase) {
		return nil, fmt.Errorf("mount source must be under %s for security: %s", airunnerBase, source)
	}

	// Validate target doesn't mount to dangerous container paths
	dangerousPaths := []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/proc", "/sys", "/dev"}
	for _, dangerous := range dangerousPaths {
		if strings.HasPrefix(target, dangerous) {
			return nil, fmt.Errorf("mounting to %s is not allowed for security", dangerous)
		}
	}

	mount := &jobv1.ContainerMount{
		Source:   cleanSource,
		Target:   target,
		ReadOnly: false,
	}

	if len(parts) == 3 && parts[2] == "ro" {
		mount.ReadOnly = true
	}

	return mount, nil
}
