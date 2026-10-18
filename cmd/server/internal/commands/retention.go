package commands

import (
	"errors"
	"time"
)

// RetentionFlags configures how long terminal jobs and their events are kept. It is shared by
// the server and cleanup commands.
type RetentionFlags struct {
	JobRetentionDays    int `help:"days to keep terminal jobs after their last update" default:"90" env:"AIRUNNER_JOB_RETENTION_DAYS"`
	EventsRetentionDays int `help:"days to keep events of terminal jobs (0 keeps them until the job is deleted)" default:"30" env:"AIRUNNER_EVENTS_RETENTION_DAYS"`
}

// Durations validates the flags and returns the job and event retention periods.
func (r RetentionFlags) Durations() (job, event time.Duration, err error) {
	if r.JobRetentionDays <= 0 {
		return 0, 0, errors.New("--job-retention-days must be positive")
	}
	if r.EventsRetentionDays < 0 {
		return 0, 0, errors.New("--events-retention-days must not be negative")
	}
	const day = 24 * time.Hour
	return time.Duration(r.JobRetentionDays) * day, time.Duration(r.EventsRetentionDays) * day, nil
}
