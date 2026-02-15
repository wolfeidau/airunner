package git

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// gitRefPattern allows alphanumeric chars, dash, underscore, slash, dot
	// This prevents command injection via malicious branch/commit names
	gitRefPattern = regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)

	// jobIDPattern validates UUID format (standard job ID format)
	jobIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
)

// validateGitURL validates that a git repository URL is safe to use.
// It only allows https:// and git:// protocols and rejects URLs with
// shell metacharacters or git-specific command injection patterns.
func validateGitURL(repoURL string) error {
	if repoURL == "" {
		return fmt.Errorf("%w: empty URL", ErrInvalidGitURL)
	}

	// Only allow http://, https:// and git:// protocols (no file://, ssh:// with potential command injection)
	allowedProtocols := []string{"http://", "https://", "git://"}
	hasValidProtocol := false
	for _, proto := range allowedProtocols {
		if strings.HasPrefix(repoURL, proto) {
			hasValidProtocol = true
			break
		}
	}
	if !hasValidProtocol {
		return fmt.Errorf("%w: must use http://, https:// or git:// protocol", ErrInvalidGitURL)
	}

	// Reject URLs with shell metacharacters or git-specific command injection patterns
	dangerous := []string{"`", "$", "&&", "||", ";", "|", "--upload-pack", "--config"}
	for _, pattern := range dangerous {
		if strings.Contains(repoURL, pattern) {
			return fmt.Errorf("%w: contains forbidden pattern: %s", ErrInvalidGitURL, pattern)
		}
	}

	return nil
}

// validateGitRef validates that a git reference (branch name or commit SHA) is safe to use.
// It only allows alphanumeric characters, dash, underscore, slash, and dot to prevent
// command injection via malicious ref names.
func validateGitRef(ref string) error {
	if ref == "" {
		return nil // Empty refs are allowed (will use default branch)
	}

	if !gitRefPattern.MatchString(ref) {
		return fmt.Errorf("%w: must contain only alphanumeric, dash, underscore, slash, or dot", ErrInvalidGitRef)
	}

	// Additional check: reject refs that look like command-line options
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "--") {
		return fmt.Errorf("%w: cannot start with dash", ErrInvalidGitRef)
	}

	return nil
}

// validateJobID validates that a job ID is in the expected UUID format.
// This prevents path traversal attacks via malicious job IDs.
func validateJobID(jobID string) error {
	if jobID == "" {
		return fmt.Errorf("%w: empty job ID", ErrInvalidJobID)
	}

	if !jobIDPattern.MatchString(jobID) {
		return fmt.Errorf("%w: must be a valid UUID", ErrInvalidJobID)
	}

	return nil
}
