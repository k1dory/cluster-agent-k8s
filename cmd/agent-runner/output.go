package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"agent-sandbox/internal/harness"
)

// The run's output reaches the control plane through a spool: the harness (or the ACP client,
// which writes under its lock from the SDK's notification handler) hands a line over and goes on,
// a sender posts the spool in batches and retries for as long as the run is alive. A writer that
// waited on the network stalled the agent: acp-go-sdk closes the connection when its inbound
// notification queue (1024) overflows, so a control plane stalled for less than a minute during a
// verbose turn killed the run.
var (
	// spoolMaxBytes and spoolMaxLines bound the output waiting for the control plane; every line
	// counts spoolLineOverhead bytes more than its text, so blank lines are bounded too. Past the
	// bounds lines are dropped (announced by one notice line), except the lines that carry the
	// run's state, which have a bounded reserve of their own above them (stateLine).
	spoolMaxBytes     = 32 << 20
	spoolMaxLines     = 100_000
	spoolReserveBytes = 1 << 20
	spoolReserveLines = 4096
	// spoolBatchLines, spoolBatchBytes and spoolBatchDelay shape a batch: a full one goes at
	// once, a partial one after the delay. The bytes stay under the control plane's body limit
	// (4 MiB); a batch over it is split on 413 anyway.
	spoolBatchLines = 50
	spoolBatchBytes = 2 << 20
	spoolBatchDelay = 500 * time.Millisecond
	// postBackoffBase and postBackoffMax bound the wait between attempts (exponential, jittered).
	postBackoffBase = 500 * time.Millisecond
	postBackoffMax  = 30 * time.Second
	// outputDrainBudget is how long the output still queued when the harness is done may take to
	// be delivered before it is given up, and how long a lone notice is retried.
	outputDrainBudget = 5 * time.Minute
	// shutdownGrace is how long delivery goes on after SIGTERM: the pod has 30 seconds by default,
	// and the result of the run (finish) still has to go after the output.
	shutdownGrace = 15 * time.Second
)

// spoolLineOverhead is what a queued line costs besides its text (its slice entry, its string
// header, the newline of the batch).
const spoolLineOverhead = 32

// stateLineBytes: a line longer than this is never a state line.
const stateLineBytes = 16 << 10

// stateLine reports whether a line carries the run's state: a turn end, a usage record, or the
// line that announces the session (the runner's acp.session, Claude Code's system init, Codex's
// thread.started). Losing one starts the next message in a new session or undercounts the cost.
// Ordinary messages carry a session_id too (stream-json): they are output like any other, or
// every line would pass the bound. It is only asked of lines that do not fit.
func stateLine(l string) bool {
	if len(l) > stateLineBytes {
		return false
	}
	if harness.IsTurnEnd(l) {
		return true
	}
	if _, _, ok := harness.ParseUsage(l); ok {
		return true
	}
	if _, ok := harness.ParseSession(l); !ok {
		return false
	}
	var v struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal([]byte(l), &v)
	return v.Type == harness.ACPSession || v.Type == "system" || v.Type == "thread.started"
}

// backoff is the wait before attempt n (n ≥ 1): base·2^(n-1) capped at max, with jitter (the
// upper half of the interval at random), so pods that lost the control plane together do not
// come back in step.
func backoff(n int, base, ceiling time.Duration) time.Duration {
	d := ceiling
	if n < 31 {
		d = min(base<<(n-1), ceiling)
	}
	if d <= 1 {
		return d
	}
	return d/2 + rand.N(d/2)
}

// sleepCtx waits d or until ctx ends; false: ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// deliveryCtx is the lifetime of a delivery the runner insists on: until budget (0: no limit)
// has passed, or shutdownGrace after parent (the process's signal context) ended.
func deliveryCtx(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	var timer *time.Timer
	if budget > 0 {
		timer = time.AfterFunc(budget, cancel)
	}
	var mu sync.Mutex
	var grace *time.Timer
	stop := context.AfterFunc(parent, func() {
		mu.Lock()
		grace = time.AfterFunc(shutdownGrace, cancel)
		mu.Unlock()
	})
	return ctx, func() {
		stop()
		if timer != nil {
			timer.Stop()
		}
		mu.Lock()
		if grace != nil {
			grace.Stop()
		}
		mu.Unlock()
		cancel()
	}
}

// outputSpool holds the run's output between the writer and the sender (see above).
type outputSpool struct {
	c     *client
	runID string
	ctx   context.Context // the sender's: ends when the run's output is given up
	stop  context.CancelFunc
	wake  chan struct{}
	done  chan struct{}

	mu     sync.Mutex
	lines  []string
	bytes  int
	closed bool
	// dropped and droppedBytes count what did not fit since the last notice.
	dropped, droppedBytes int
}

// newOutputSpool starts the sender. parent is the process's signal context: after SIGTERM the
// output is delivered for shutdownGrace more, then given up.
func newOutputSpool(parent context.Context, c *client, runID string) *outputSpool {
	ctx, stop := deliveryCtx(parent, 0)
	s := &outputSpool{c: c, runID: runID, ctx: ctx, stop: stop, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go s.send()
	return s
}

func (s *outputSpool) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// add queues a line and never blocks. A line that does not fit is dropped and counted; the next
// one that fits is preceded by a single notice saying what was lost. A state line that does not
// fit goes into the reserve above the bounds; past the reserve it is dropped too. The notice
// itself is small and always goes in, so the spool never holds more than the bounds, the reserve
// and one notice per drop announced.
func (s *outputSpool) add(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	cost := len(line) + spoolLineOverhead
	fits := func(maxBytes, maxLines int) bool {
		return s.bytes+cost <= maxBytes && len(s.lines) < maxLines
	}
	if !fits(spoolMaxBytes, spoolMaxLines) &&
		!(fits(spoolMaxBytes+spoolReserveBytes, spoolMaxLines+spoolReserveLines) && stateLine(line)) {
		s.dropped++
		s.droppedBytes += len(line)
		return
	}
	s.noticeDropsLocked()
	s.lines = append(s.lines, line)
	s.bytes += cost
	s.signal()
}

// read spools r's lines until EOF or a read error (readLines: an oversized line becomes a
// notice), each also printed to the pod's stdout for kubectl logs and log shipping.
func (s *outputSpool) read(r io.Reader, onLine func(string)) {
	lines := make(chan string)
	go func() {
		readLines(r, maxOutputLine, lines)
		close(lines)
	}()
	for l := range lines {
		fmt.Println(l)
		if onLine != nil {
			onLine(l)
		}
		s.add(l)
	}
}

// emit spools a line the runner writes itself (the ACP client's lines and notices), with the
// rules of read: one line per newline, an oversized one replaced by a notice. It is called from
// acp-go-sdk's notification handler and costs a lock and a copy: the SDK closes the connection
// when its queue (1024) fills behind a slow handler, which a burst of updates (a session/load
// replaying a long history, a verbose turn) does to a handler that hands every line through a
// pipe and a reader.
func (s *outputSpool) emit(text string) {
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		l = strings.TrimSuffix(l, "\r")
		if len(l) > maxOutputLine {
			l = fmt.Sprintf("[agent-runner] dropped an output line of %d bytes (limit %d)", len(l), maxOutputLine)
		}
		fmt.Println(l)
		s.add(l)
	}
}

func (s *outputSpool) noticeDropsLocked() {
	if s.dropped == 0 {
		return
	}
	n := fmt.Sprintf("[agent-runner] dropped %d output line(s), %d bytes: the control plane did not take the output in time (spool limit %d bytes)",
		s.dropped, s.droppedBytes, spoolMaxBytes)
	s.dropped, s.droppedBytes = 0, 0
	s.lines = append(s.lines, n)
	s.bytes += len(n) + spoolLineOverhead
}

// close ends the output: what is queued is delivered within budget (or the shutdown grace), then
// given up. It returns once the sender is done.
func (s *outputSpool) close(budget time.Duration) {
	s.mu.Lock()
	s.noticeDropsLocked()
	s.closed = true
	s.signal()
	s.mu.Unlock()
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
		s.stop()
		<-s.done
	}
	s.stop()
}

// take waits for a batch: a full one at once, a partial one after spoolBatchDelay or when the
// output ends. ok is false when the output ended and everything was taken, or the spool gave up.
func (s *outputSpool) take() (batch []string, ok bool) {
	var timer <-chan time.Time
	waited := false
	for {
		s.mu.Lock()
		n, size := 0, 0
		for n < len(s.lines) && n < spoolBatchLines && (n == 0 || size+len(s.lines[n]) <= spoolBatchBytes) {
			size += len(s.lines[n])
			n++
		}
		full := n == spoolBatchLines || n < len(s.lines)
		if n > 0 && (full || waited || s.closed) {
			batch = append([]string(nil), s.lines[:n]...)
			clear(s.lines[:n]) // the strings are the batch's now, not the backing array's
			s.lines = s.lines[n:]
			s.bytes -= size + n*spoolLineOverhead
			s.mu.Unlock()
			return batch, true
		}
		if n == 0 && s.closed {
			s.mu.Unlock()
			return nil, false
		}
		s.mu.Unlock()
		if n > 0 && timer == nil {
			t := time.NewTimer(spoolBatchDelay)
			defer t.Stop()
			timer = t.C
		}
		select {
		case <-s.wake:
		case <-timer:
			waited = true
		case <-s.ctx.Done():
			return nil, false
		}
	}
}

func (s *outputSpool) send() {
	defer close(s.done)
	for {
		batch, ok := s.take()
		if !ok {
			break
		}
		if err := s.c.postBatch(s.ctx, s.runID, batch); err != nil {
			s.mu.Lock()
			lost := len(batch) + len(s.lines)
			s.lines, s.bytes = nil, 0
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "agent-runner: run %s: %d output line(s) not delivered: %v\n", s.runID, lost, err)
			return
		}
	}
	s.mu.Lock()
	lost := len(s.lines)
	s.lines, s.bytes = nil, 0
	s.mu.Unlock()
	if lost > 0 {
		fmt.Fprintf(os.Stderr, "agent-runner: run %s: %d output line(s) not delivered: %v\n", s.runID, lost, s.ctx.Err())
	}
}

// post delivers a few lines outside a run's output stream (a notice before the harness starts),
// retried within outputDrainBudget.
func (c *client) post(ctx context.Context, runID string, lines []string) {
	dctx, done := deliveryCtx(ctx, outputDrainBudget)
	defer done()
	if err := c.postBatch(dctx, runID, lines); err != nil {
		fmt.Fprintf(os.Stderr, "agent-runner: run %s: %d output line(s) not delivered: %v\n", runID, len(lines), err)
	}
}

// postBatch ships a batch of output lines and insists on an acknowledgement until ctx ends:
// transient failures are retried with backoff under the same X-Batch-Id (the control plane skips
// lines it already stored, so a retry never duplicates them), a 413 splits the batch, a single
// oversized line is dropped with a notice. 403/404: the run is not ours any more, nothing to
// deliver. The error is ctx's when it ended first.
func (c *client) postBatch(ctx context.Context, runID string, lines []string) error {
	body := []byte(strings.Join(lines, "\n") + "\n")
	batch := newBatchID()
	for attempt := 0; ; attempt++ {
		if attempt > 0 && !sleepCtx(ctx, backoff(attempt, postBackoffBase, postBackoffMax)) {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/runs/"+runID+"/events", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-Batch-Id", batch) // same id on every retry: the server skips lines it already stored
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logRetry(attempt, err)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusRequestEntityTooLarge:
			var ack struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(data, &ack)
			stored := storedCount(ack.Error)
			rest := lines[min(stored, len(lines)):]
			if len(rest) == len(lines) && len(lines) == 1 {
				fmt.Fprintf(os.Stderr, "agent-runner: dropping a %d-byte output line: %s\n", len(lines[0]), ack.Error)
				return nil
			}
			if len(rest) == len(lines) {
				if err := c.postBatch(ctx, runID, rest[:len(rest)/2]); err != nil {
					return err
				}
				return c.postBatch(ctx, runID, rest[len(rest)/2:])
			}
			if len(rest) == 0 {
				return nil
			}
			return c.postBatch(ctx, runID, rest)
		case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusNotFound:
			fmt.Fprintf(os.Stderr, "agent-runner: post output: %s: %s\n", resp.Status, strings.TrimSpace(string(data)))
			return nil
		default:
			logRetry(attempt, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data))))
		}
	}
}

// logRetry reports a failed attempt: the first, then every tenth, so an outage is visible in the
// pod's log without a line per retry.
func logRetry(attempt int, err error) {
	if attempt%10 == 0 {
		fmt.Fprintf(os.Stderr, "agent-runner: post output (attempt %d, will retry): %v\n", attempt+1, err)
	}
}
