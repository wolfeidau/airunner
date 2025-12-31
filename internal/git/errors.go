package git

import "errors"

var (
	// ErrInvalidGitURL indicates the git repository URL is invalid or potentially malicious
	ErrInvalidGitURL = errors.New("invalid git repository URL")
	// ErrInvalidGitRef indicates the git reference (branch/commit) is invalid or potentially malicious
	ErrInvalidGitRef = errors.New("invalid git reference")
	// ErrInvalidJobID indicates the job ID format is invalid
	ErrInvalidJobID = errors.New("invalid job ID format")
	// ErrCloneFailed indicates git clone operation failed
	ErrCloneFailed = errors.New("git clone failed")
	// ErrCheckoutFailed indicates git checkout operation failed
	ErrCheckoutFailed = errors.New("git checkout failed")
)
