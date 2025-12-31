# Implementation Plan: Job Events Drill-Down for Dashboard

## Overview

Add click-through navigation from the dashboard job list to view real-time job events (console output and lifecycle events) using hash-based routing.

**User Requirements:**
- ✅ Hash-based routing (`#job-{jobId}`) for bookmarking - NO React Router
- ✅ Display console output (stdout/stderr) + process lifecycle events
- ✅ Real-time event streaming as jobs run
- ✅ Browser back/forward button support

**Architecture:**
- Keep existing multi-page app with server-side routing
- Single-file implementation in `dashboard.tsx`
- Use Connect-Web directly for streaming (Connect Query doesn't support streaming RPCs)
- Follow CLI monitor patterns for event handling

---

## Implementation Phases

### Phase 1: Hash Routing Foundation (30 min)

**Goal:** Enable hash-based navigation between job list and event view.

**Tasks:**
1. Add `selectedJobId` state to Dashboard component
2. Add `useEffect` hook to listen for `hashchange` events
3. Parse hash format `#job-{jobId}` to extract job ID
4. Add conditional rendering: show `JobEventsView` when hash present, else show job list
5. Test by manually typing `#job-test` in URL bar

**Key Code Pattern:**
```typescript
const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

useEffect(() => {
  const handleHashChange = () => {
    const hash = window.location.hash;
    if (hash.startsWith('#job-')) {
      setSelectedJobId(hash.substring(5));
    } else {
      setSelectedJobId(null);
    }
  };
  handleHashChange(); // Initial load
  window.addEventListener('hashchange', handleHashChange);
  return () => window.removeEventListener('hashchange', handleHashChange);
}, []);
```

---

### Phase 2: Clickable Job Rows (20 min)

**Goal:** Make job table rows clickable with keyboard accessibility.

**Tasks:**
1. Add `handleJobClick` function that sets `window.location.hash`
2. Modify `<tr>` elements with:
   - `onClick` handler
   - `onKeyDown` handler (Enter/Space keys)
   - `tabIndex={0}` for keyboard focus
   - `role="button"` for screen readers
   - `aria-label` describing action
3. Add CSS for hover and focus states
4. Test keyboard navigation (Tab, Enter)

**Key Code Pattern:**
```typescript
<tr
  className="job-row job-row-clickable"
  onClick={() => window.location.hash = `#job-${job.jobId}`}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      window.location.hash = `#job-${job.jobId}`;
    }
  }}
  tabIndex={0}
  role="button"
  aria-label={`View details for job ${job.jobId?.slice(0, 8)}`}
>
```

---

### Phase 3: Event Streaming Hook (45 min)

**Goal:** Create custom React hook to consume streaming events.

**Tasks:**
1. Import Connect-Web client and protobuf types
2. Create `useJobEventStream(jobId: string)` custom hook
3. Use `createPromiseClient` with `JobEventsService`
4. Call `streamJobEvents` with async iteration
5. Accumulate events in state array
6. Detect job completion on `PROCESS_END` event
7. Use `AbortController` for cleanup
8. Return `{ events, isConnecting, error, jobCompleted }`

**Key Code Pattern:**
```typescript
function useJobEventStream(jobId: string) {
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [isConnecting, setIsConnecting] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [jobCompleted, setJobCompleted] = useState(false);

  useEffect(() => {
    const abortController = new AbortController();

    async function streamEvents() {
      try {
        const eventsClient = createPromiseClient(JobEventsService, finalTransport);
        const stream = eventsClient.streamJobEvents(
          { jobId, fromSequence: 0n, eventFilter: [] },
          { signal: abortController.signal }
        );

        setIsConnecting(false);

        for await (const response of stream) {
          if (response.event) {
            setEvents(prev => [...prev, response.event!]);
            if (response.event.eventType === EventType.PROCESS_END) {
              setJobCompleted(true);
            }
          }
        }
      } catch (err: any) {
        if (err.name !== 'AbortError') {
          setError(err.message);
          setIsConnecting(false);
        }
      }
    }

    streamEvents();
    return () => abortController.abort();
  }, [jobId]);

  return { events, isConnecting, error, jobCompleted };
}
```

**Important:** Use `finalTransport` (already defined in dashboard.tsx) for the Connect client.

---

### Phase 4: Event Display Components (60 min)

**Goal:** Render events with console output and lifecycle information.

**Component Structure:**
```
JobEventsView
├── EventsHeader (back button, job ID)
├── JobCompletionBanner (if completed)
└── EventsConsole
    ├── EventItem (repeated)
    │   ├── ProcessStart/End/Error
    │   └── OutputBatchRenderer
    └── Auto-scroll anchor
```

**Tasks:**

1. **JobEventsView** - Container component
   - Call `useJobEventStream(jobId)`
   - Handle loading/error/empty states
   - Render header, banner, console

2. **EventsHeader** - Navigation header
   - Back button: `onClick={() => window.location.hash = ''}`
   - Display job ID (first 12 chars)

3. **EventsConsole** - Scrollable event container
   - Map events to `EventItem` components
   - Add `consoleEndRef` for auto-scroll target
   - Auto-scroll on new events

4. **EventItem** - Event type dispatcher
   - Switch on `event.eventType`
   - Render lifecycle events (START, END, ERROR) with timestamps
   - Skip heartbeat events (not requested by user)
   - Delegate OUTPUT_BATCH to `OutputBatchRenderer`

5. **OutputBatchRenderer** - Console output renderer
   - Unpack `batch.outputs` array
   - Reconstruct timestamps: `firstTimestampMs + timestampDeltaMs`
   - Decode `Uint8Array` to string with `TextDecoder`
   - Apply styles based on `streamType` (STDOUT vs STDERR)

**Critical Pattern - OutputBatch Unpacking:**
```typescript
function OutputBatchRenderer({ batch }: { batch: OutputBatchEvent }) {
  return (
    <>
      {batch.outputs.map((output, idx) => {
        // Reconstruct absolute timestamp
        const outputTimestampMs = Number(batch.firstTimestampMs) + output.timestampDeltaMs;
        const outputTime = new Date(outputTimestampMs);
        const timestamp = outputTime.toLocaleTimeString('en-US', {
          hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
        });

        // Decode bytes to string
        const text = new TextDecoder('utf-8', { fatal: false }).decode(output.output);

        const className = output.streamType === StreamType.STDERR
          ? 'output-stderr'
          : 'output-stdout';

        return (
          <div key={idx} className={`output-line ${className}`}>
            <span className="output-timestamp">[{timestamp}]</span>
            <span className="output-text">{text}</span>
          </div>
        );
      })}
    </>
  );
}
```

**Auto-scroll Implementation:**
```typescript
const consoleEndRef = useRef<HTMLDivElement>(null);

useEffect(() => {
  consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
}, [events]);

// In JSX:
<div ref={consoleEndRef} />
```

---

### Phase 5: CSS Styling (30 min)

**Goal:** Add Nord-themed styles for events view.

**Add to `dashboard.css`:**

**Layout Components:**
- `.events-container` - Full-height flex column
- `.events-header` - Top bar with back button and title
- `.events-console` - Scrollable event area with monospace font

**Event Styles:**
- `.event-lifecycle` - Lifecycle event base (START/END/ERROR)
- `.event-start` - Blue border/text (Nord8)
- `.event-success` - Green border/text (Nord14)
- `.event-failed` - Red border/text (Nord11)
- `.event-error` - Red with background tint

**Output Styles:**
- `.output-line` - Single line container
- `.output-stdout` - Normal text color (Nord4)
- `.output-stderr` - Red text (Nord11)
- `.output-timestamp` - Gray timestamp (Nord3)
- `.output-text` - Monospace with word wrap

**State Styles:**
- `.events-loading` - Centered spinner
- `.events-empty` - Centered message
- `.events-error` - Centered error display
- `.events-banner-completed` - Green completion banner

**Interactive Styles:**
- `.job-row-clickable` - Cursor pointer
- `.job-row-clickable:focus` - Blue outline (Nord8)
- `.btn-back` - Border button with hover state

**Key CSS for Spinner:**
```css
.spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--nord2);
  border-top-color: var(--nord8);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
```

---

### Phase 6: Testing & Polish (30 min)

**Manual Testing Checklist:**

**Hash Routing:**
- [ ] Click job → URL updates to `#job-{id}`
- [ ] Browser back → returns to job list
- [ ] Browser forward → returns to event view
- [ ] Direct URL with hash → opens event view
- [ ] Empty hash → shows job list

**Event Streaming:**
- [ ] Loading spinner appears while connecting
- [ ] Events appear in real-time
- [ ] Stdout in normal color, stderr in red
- [ ] Process START event displays
- [ ] Process END event displays with exit code
- [ ] Completion banner appears

**UI/UX:**
- [ ] Auto-scroll to new events
- [ ] Back button works
- [ ] Keyboard navigation (Tab + Enter)
- [ ] Focus outline visible

**Error Handling:**
- [ ] Invalid job ID shows error
- [ ] Network error shows error
- [ ] Empty state when no events

**Integration Test:**
1. Submit job via CLI: `./bin/airunner-cli submit --server=https://localhost:8993 --queue=default github.com/example/repo`
2. Click job in dashboard
3. Verify events stream in real-time
4. Verify completion banner after job ends

---

## Critical Files to Modify

### 1. `/Users/markw/Code/notgopath/airunner/ui/pages/dashboard.tsx`

**Changes:** (~250 lines added)

**Add imports:**
```typescript
import { createPromiseClient } from "@connectrpc/connect";
import { JobEventsService } from "../../api/gen/proto/es/job/v1/job_pb";
import {
  JobEvent,
  EventType,
  StreamType,
  OutputBatchEvent,
  ProcessStartEvent,
  ProcessEndEvent,
  ProcessErrorEvent
} from "../../api/gen/proto/es/job/v1/job_pb";
```

**Add components:**
- `useJobEventStream` hook
- `JobEventsView` component
- `EventsHeader` component
- `EventsConsole` component
- `EventItem` component
- `OutputBatchRenderer` component

**Modify:**
- Dashboard component: add hash routing state and effect
- Job table rows: add click handlers and accessibility props

---

### 2. `/Users/markw/Code/notgopath/airunner/ui/pages/dashboard.css`

**Changes:** (~150 lines added)

Add all event view styles:
- Events container and header layout
- Console output styling with monospace font
- Lifecycle event badges (START/END/ERROR)
- Loading/empty/error states
- Clickable row styles
- Auto-scroll behavior

---

## Reference Files (Read-Only)

**Event handling patterns:**
- `/Users/markw/Code/notgopath/airunner/cmd/cli/internal/commands/monitor.go` (lines 182-290)
  - Event type switching
  - OutputBatch unpacking (lines 236-273)
  - Timestamp reconstruction pattern

**TypeScript types:**
- `/Users/markw/Code/notgopath/airunner/api/gen/proto/es/job/v1/job_pb.ts`
  - `JobEvent` with discriminated union `eventData.case`
  - `EventType`, `StreamType` enums
  - `OutputBatchEvent`, `OutputItem` structures

**Utilities:**
- `/Users/markw/Code/notgopath/airunner/ui/lib/proto_convert.ts`
  - `timestampToJsDate()` for timestamp conversion

---

## Key Technical Details

### Event Data Structure

Events use a **discriminated union** in TypeScript:

```typescript
event.eventData.case === "processStart"  // Type guard
event.eventData.value.pid                // Access nested data
```

### Timestamp Reconstruction

OutputBatch uses delta encoding for efficiency:

```typescript
// firstTimestampMs: absolute Unix milliseconds (int64)
// timestampDeltaMs: offset from first item (int32)
const absoluteMs = Number(batch.firstTimestampMs) + output.timestampDeltaMs;
const date = new Date(absoluteMs);
```

### Stream Cleanup

Critical for preventing memory leaks:

```typescript
const abortController = new AbortController();
// ...
return () => abortController.abort();  // Cleanup in useEffect
```

### TextDecoder Error Handling

Prevent errors on invalid UTF-8:

```typescript
new TextDecoder('utf-8', { fatal: false })  // Don't throw on invalid sequences
```

---

## Potential Issues & Solutions

**Issue:** Large event output causes performance problems
**Solution:** Limit visible events to last 500 with `events.slice(-500)`

**Issue:** Auto-scroll fights user when scrolling up
**Solution:** Check scroll position before auto-scrolling (optional enhancement)

**Issue:** Stream doesn't cleanup on unmount
**Solution:** Use AbortController in useEffect cleanup (already in plan)

**Issue:** Invalid job ID in hash
**Solution:** Handle stream errors gracefully, show error message

---

## Estimated Timeline

- Phase 1: Hash routing - 30 min
- Phase 2: Clickable rows - 20 min
- Phase 3: Streaming hook - 45 min
- Phase 4: Event components - 60 min
- Phase 5: CSS styling - 30 min
- Phase 6: Testing - 30 min

**Total: ~3.5 hours**

---

## Success Criteria

✅ Clicking job updates URL hash and shows event view
✅ Browser back/forward buttons work correctly
✅ Events stream in real-time as job runs
✅ Console output displays with timestamps
✅ Stdout and stderr are visually distinct
✅ Process lifecycle events show clearly
✅ Completion banner appears after job ends
✅ Loading/error/empty states render properly
✅ Keyboard navigation works with Tab + Enter
✅ No memory leaks (stream cleanup on unmount)
