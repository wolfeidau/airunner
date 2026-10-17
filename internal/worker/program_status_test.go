package worker

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	consolestream "github.com/wolfeidau/console-stream"
	"github.com/wolfeidau/osc7501"
)

func newCollectingExecutor(t *testing.T) (*JobExecutor, func() []*jobv1.JobEvent) {
	t.Helper()

	var mu sync.Mutex
	var events []*jobv1.JobEvent
	batcher := NewEventBatcher(nil, func(event *jobv1.JobEvent) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
		return nil
	})

	return NewJobExecutor(nil, "token", batcher), func() []*jobv1.JobEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]*jobv1.JobEvent(nil), events...)
	}
}

func TestHandleEventProgramStatus(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.handleEvent(consolestream.Event{Event: &consolestream.ProgramStatus{
		State:    "working",
		ID:       "build",
		Kind:     "build",
		App:      "make",
		Title:    "Building",
		Msg:      "compiling",
		Progress: 42,
	}}, "job-1")
	require.NoError(t, err)

	events := got()
	require.Len(t, events, 1)
	require.Equal(t, jobv1.EventType_EVENT_TYPE_PROGRAM_STATUS, events[0].EventType)

	ps := events[0].GetProgramStatus()
	require.NotNil(t, ps)
	require.Equal(t, "working", ps.State)
	require.Equal(t, "build", ps.Id)
	require.Equal(t, "build", ps.Kind)
	require.Equal(t, "make", ps.App)
	require.Equal(t, "Building", ps.Title)
	require.Equal(t, "compiling", ps.Msg)
	require.Equal(t, int32(42), ps.Progress)
	require.NotNil(t, events[0].Timestamp)
}

func TestExecuteCapturesProgramStatus(t *testing.T) {
	je, got := newCollectingExecutor(t)

	report := osc7501.Report{State: osc7501.StateWorking, ID: "build", App: "tester", Progress: 50, Msg: "half way"}
	require.NoError(t, report.Validate())

	job := &jobv1.Job{
		JobId: "job-1",
		JobParams: &jobv1.JobParams{
			Command:     "sh",
			Args:        []string{"-c", `printf 'before\n'; printf '%s' "$1"; printf 'after\n'`, "sh", string(report.Encode())},
			ProcessType: jobv1.ProcessType_PROCESS_TYPE_PIPE,
		},
	}

	require.NoError(t, je.Execute(context.Background(), job))

	var statusSeq int64 = -1
	var beforeSeq, afterSeq int64 = -1, -1
	for _, ev := range got() {
		switch ev.EventType {
		case jobv1.EventType_EVENT_TYPE_PROGRAM_STATUS:
			statusSeq = ev.Sequence
			ps := ev.GetProgramStatus()
			require.NotNil(t, ps)
			require.Equal(t, "working", ps.State)
			require.Equal(t, "build", ps.Id)
			require.Equal(t, "tester", ps.App)
			require.Equal(t, "half way", ps.Msg)
			require.Equal(t, int32(50), ps.Progress)
		case jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH:
			for _, out := range ev.GetOutputBatch().Outputs {
				if bytes.Contains(out.Output, []byte("before")) {
					beforeSeq = ev.GetOutputBatch().EndSequence
				}
				if bytes.Contains(out.Output, []byte("after")) {
					afterSeq = ev.GetOutputBatch().StartSequence
				}
			}
		}
	}

	require.GreaterOrEqual(t, statusSeq, int64(0), "program status event not published")
	require.GreaterOrEqual(t, beforeSeq, int64(0), "output before status not found")
	require.GreaterOrEqual(t, afterSeq, int64(0), "output after status not found")
	require.Less(t, beforeSeq, statusSeq, "status must be sequenced after preceding output")
	require.Less(t, statusSeq, afterSeq, "status must be sequenced before following output")
}
