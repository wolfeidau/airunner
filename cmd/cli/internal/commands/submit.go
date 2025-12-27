package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/google/uuid"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
	"gopkg.in/yaml.v3"
)

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
}

type SubmitCmd struct {
	Server           string            `help:"Server URL" default:"https://localhost:443"`
	Queue            string            `help:"Queue name" default:"default"`
	Repository       string            `arg:"" help:"Repository URL to process"`
	Commit           string            `help:"Commit hash or identifier" default:"main"`
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
	CACert           string            `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert       string            `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey        string            `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
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

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	// Create clients
	config := client.Config{
		ServerURL:  s.Server,
		Timeout:    s.Timeout,
		Debug:      globals.Debug,
		CACert:     s.CACert,
		ClientCert: s.ClientCert,
		ClientKey:  s.ClientKey,
	}
	clients, err := client.NewClients(config, connect.WithInterceptors(otelInterceptor))
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
		},
	}

	resp, err := clients.Job.EnqueueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return "", fmt.Errorf("failed to enqueue job: %w", err)
	}

	return resp.Msg.JobId, nil
}
