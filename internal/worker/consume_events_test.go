package worker

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	consolestream "github.com/wolfeidau/console-stream"
)

type scripted struct {
	event consolestream.Event
	err   error
}

func ev(e consolestream.StreamEvent) scripted {
	return scripted{event: consolestream.Event{Event: e}}
}

// fakeSeq yields the scripted items in order, stopping when the consumer stops.
// pulled records how many items were yielded.
func fakeSeq(items []scripted, pulled *int) iter.Seq2[consolestream.Event, error] {
	return func(yield func(consolestream.Event, error) bool) {
		for _, it := range items {
			if pulled != nil {
				*pulled++
			}
			if !yield(it.event, it.err) {
				return
			}
		}
	}
}

// newFailingExecutor returns an executor whose onFlush always fails.
func newFailingExecutor() *JobExecutor {
	batcher := NewEventBatcher(nil, func(*jobv1.JobEvent) error {
		return errors.New("wal write failed")
	})
	return NewJobExecutor("token", batcher)
}

func eventTypes(events []*jobv1.JobEvent) []jobv1.EventType {
	types := make([]jobv1.EventType, 0, len(events))
	for _, e := range events {
		types = append(types, e.EventType)
	}
	return types
}

func TestConsumeEventsContinuesAfterProcessEnd(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessStart{PID: 1}),
		ev(&consolestream.ProcessEnd{ExitCode: 0}),
		ev(&consolestream.ContainerRemove{ContainerID: "c1"}),
	}, nil), "job-1")
	require.NoError(t, err)
	require.Equal(t, []jobv1.EventType{
		jobv1.EventType_EVENT_TYPE_PROCESS_START,
		jobv1.EventType_EVENT_TYPE_PROCESS_END,
		jobv1.EventType_EVENT_TYPE_CONTAINER_REMOVE,
	}, eventTypes(got()))
}

func TestConsumeEventsExitErrorStillPublishesContainerRemove(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessEnd{ExitCode: 3}),
		ev(&consolestream.ContainerRemove{ContainerID: "c1"}),
	}, nil), "job-1")
	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 3, exitErr.Code)
	require.Contains(t, eventTypes(got()), jobv1.EventType_EVENT_TYPE_CONTAINER_REMOVE)
}

func TestConsumeEventsProcessErrorThenProcessEnd(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessError{Error: errors.New("eof"), Message: "Container log stream failed"}),
		ev(&consolestream.ProcessEnd{ExitCode: 0}),
	}, nil), "job-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Container log stream failed")
	require.Contains(t, eventTypes(got()), jobv1.EventType_EVENT_TYPE_PROCESS_ERROR)
}

func TestConsumeEventsProcessErrorJoinsExitError(t *testing.T) {
	je, _ := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessError{Error: errors.New("eof"), Message: "Container log stream failed"}),
		ev(&consolestream.ProcessEnd{ExitCode: 2}),
	}, nil), "job-1")
	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 2, exitErr.Code)
}

func TestConsumeEventsProcessErrorWithoutProcessEnd(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessStart{PID: 1}),
		ev(&consolestream.ProcessError{Error: errors.New("boom"), Message: "Container wait failed"}),
	}, nil), "job-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Container wait failed")
	require.Contains(t, eventTypes(got()), jobv1.EventType_EVENT_TYPE_PROCESS_ERROR)
}

func TestConsumeEventsNoProcessEnd(t *testing.T) {
	je, _ := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessStart{PID: 1}),
	}, nil), "job-1")
	require.ErrorContains(t, err, "without a ProcessEnd")
}

func TestConsumeEventsIteratorErrorAfterProcessEnd(t *testing.T) {
	je, got := newCollectingExecutor(t)
	defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessEnd{ExitCode: 0}),
		{err: errors.New("stream broke")},
	}, nil), "job-1")
	require.ErrorContains(t, err, "stream broke")
	require.Contains(t, eventTypes(got()), jobv1.EventType_EVENT_TYPE_PROCESS_ERROR)
}

func TestConsumeEventsStopsOnFlushFailure(t *testing.T) {
	je := newFailingExecutor()
	var pulled int
	err := je.consumeEvents(fakeSeq([]scripted{
		ev(&consolestream.ProcessStart{PID: 1}),
		ev(&consolestream.ProcessEnd{ExitCode: 0}),
		ev(&consolestream.ContainerRemove{ContainerID: "c1"}),
	}, &pulled), "job-1")
	require.ErrorContains(t, err, "wal write failed")
	require.Equal(t, 1, pulled, "consumption must stop after the first failure")
}

func TestHandleEventOutputChunking(t *testing.T) {
	for _, size := range []int{maxSingleOutputBytes, maxSingleOutputBytes + 1, 3 * 1024 * 1024} {
		t.Run(time.Duration(size).String(), func(t *testing.T) {
			je, got := newCollectingExecutor(t)

			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 251)
			}

			require.NoError(t, je.handleEvent(consolestream.Event{Event: &consolestream.OutputData{Data: data}}, "job-1"))
			require.NoError(t, je.batcher.Stop(context.Background()))

			var out bytes.Buffer
			for _, e := range got() {
				if e.EventType != jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH {
					continue
				}
				for _, item := range e.GetOutputBatch().Outputs {
					require.LessOrEqual(t, len(item.Output), maxSingleOutputBytes)
					out.Write(item.Output)
				}
			}
			require.True(t, bytes.Equal(data, out.Bytes()), "output bytes differ: got %d want %d", out.Len(), len(data))
		})
	}
}

func TestExecutePropagatesRecordingFailure(t *testing.T) {
	je := newFailingExecutor()

	job := &jobv1.Job{
		JobId: "job-1",
		JobParams: &jobv1.JobParams{
			Command:     "sh",
			Args:        []string{"-c", "echo hi"},
			ProcessType: jobv1.ProcessType_PROCESS_TYPE_PIPE,
		},
	}
	require.ErrorContains(t, je.Execute(context.Background(), job), "wal write failed")
}
