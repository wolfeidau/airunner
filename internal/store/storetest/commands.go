package storetest

// CommandKind names a command type.
type CommandKind string

// Command kinds.
const (
	KindEnqueue  CommandKind = "enqueue"
	KindAcquire  CommandKind = "acquire"
	KindRenew    CommandKind = "renew"
	KindRelease  CommandKind = "release"
	KindComplete CommandKind = "complete"
	KindPublish  CommandKind = "publish"
	KindExpire   CommandKind = "expire"
	KindCancel   CommandKind = "cancel"
	KindList     CommandKind = "list"
)

// AllKinds lists every command kind in a fixed order.
var AllKinds = []CommandKind{
	KindEnqueue, KindAcquire, KindRenew, KindRelease, KindComplete,
	KindPublish, KindExpire, KindCancel, KindList,
}

// Command is a model input. Time (Now, Lease) is in caller-defined integer units.
type Command interface{ Kind() CommandKind }

// Enqueue creates a job, or returns the existing one for an idempotent retry.
type Enqueue struct {
	Caller             Caller
	RequestID          string
	Queue              string
	Fingerprint        string
	MaxAttempts        *int
	DefaultMaxAttempts int
	Handle             JobHandle // used only if a job is created
}

// Acquire leases up to Max oldest eligible jobs; Receipts must be fresh.
type Acquire struct {
	Caller   Caller
	Queue    string
	Max      int
	Receipts []Receipt
	Now      int64
	Lease    int64
}

// Renew extends a live lease.
type Renew struct {
	Caller  Caller
	Handle  JobHandle
	Receipt Receipt
	Now     int64
	Lease   int64
}

// Release gives up a live lease.
type Release struct {
	Caller  Caller
	Handle  JobHandle
	Receipt Receipt
	Now     int64
}

// Complete finishes the running attempt.
type Complete struct {
	Caller        Caller
	Handle        JobHandle
	Receipt       Receipt
	Now           int64
	Success       bool
	FinalSequence int64
}

// Publish commits a batch of event records for the running attempt.
type Publish struct {
	Caller  Caller
	Handle  JobHandle
	Receipt Receipt
	Now     int64
	Events  []Record
}

// Expire is the reaper: it reclaims every lease with deadline <= Now.
type Expire struct{ Now int64 }

// Cancel cancels a SCHEDULED or RUNNING job.
type Cancel struct {
	Caller Caller
	Handle JobHandle
	Now    int64
}

// List returns handles in the caller's org and queue.
type List struct {
	Caller Caller
	Queue  string
}

func (Enqueue) Kind() CommandKind  { return KindEnqueue }
func (Acquire) Kind() CommandKind  { return KindAcquire }
func (Renew) Kind() CommandKind    { return KindRenew }
func (Release) Kind() CommandKind  { return KindRelease }
func (Complete) Kind() CommandKind { return KindComplete }
func (Publish) Kind() CommandKind  { return KindPublish }
func (Expire) Kind() CommandKind   { return KindExpire }
func (Cancel) Kind() CommandKind   { return KindCancel }
func (List) Kind() CommandKind     { return KindList }
