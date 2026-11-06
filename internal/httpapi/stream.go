package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"agent-sandbox/internal/events"
)

// sseItem is one frame of a stream: its id (the event id a client resumes from with
// Last-Event-ID), its SSE event name and the JSON data.
type sseItem struct {
	ID    int64
	Event string
	Data  any
	// Cursor, when set, is the frame's SSE id instead of ID: what the client must hand back
	// to resume (a bounded trace adds its replay boundary).
	Cursor string
}

// ssePage reads the durable log after a cursor: the frames to send and the cursor to continue
// from. next may run past the last frame (a conversation skips events that are not turns);
// next == after means the log has nothing more for now.
type ssePage func(ctx context.Context, after int64) (items []sseItem, next int64, err error)

// sseOpen subscribes a stream to its wake-ups (and does whatever must precede that, such as
// reading a replay boundary). An error ends the stream with the error frame. checkpoint, when
// set, is sent first as the id of an `event: checkpoint` frame without data: the cursor a
// client must resume with even if no event ever reaches it (a bounded trace's boundary).
type sseOpen func(ctx context.Context) (wake <-chan struct{}, cancel func(), checkpoint string, err error)

// hubWake is the sseOpen of a stream that only needs the hub's wake-ups.
func hubWake(h *events.Hub, key string, types ...string) sseOpen {
	return func(context.Context) (<-chan struct{}, func(), string, error) {
		wake, cancel := h.Wake(key, types...)
		return wake, cancel, "", nil
	}
}

// ssePageSize is how many events one read of the log takes.
const ssePageSize = 500

// streamSSE serves the events, messages and trace streams the same way: everything is read
// from the durable log from the cursor of the last frame sent, and the hub only says when to
// look again. A client too slow to keep up therefore only gets its frames later, never loses
// them, and a reconnect with Last-Event-ID resumes exactly where the last frame left off.
// open subscribes before the first read: an event appended between the first read and the
// wait is then still a pending wake-up. The keepalive tick reads the log too, so a wake-up
// missed elsewhere (a listener reconnecting) delays frames by one tick at most.
//
// A failed open or read ends the stream with an error frame (the client reconnects from its last id);
// a failed write ends it silently, the client is gone.
func streamSSE(w http.ResponseWriter, r *http.Request, open sseOpen, keepalive time.Duration, after int64, page ssePage) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	errWrite := errors.New("client gone")
	drain := func() error {
		for {
			items, next, err := page(ctx, after)
			if err != nil {
				return err
			}
			for _, it := range items {
				b, err := json.Marshal(it.Data)
				if err != nil {
					return err
				}
				id := it.Cursor
				if id == "" {
					id = strconv.FormatInt(it.ID, 10)
				}
				if _, err := fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", id, it.Event, b); err != nil {
					return errWrite
				}
			}
			if len(items) > 0 {
				fl.Flush()
			}
			if next <= after {
				return nil
			}
			after = next
		}
	}
	fail := func(err error) {
		if errors.Is(err, errWrite) || ctx.Err() != nil {
			return
		}
		noteInternal(w, err)
		b, _ := json.Marshal(ErrorBody{Code: codeFor(http.StatusInternalServerError), RequestID: w.Header().Get("X-Request-Id"),
			Error: "reading the event log failed; reconnect with Last-Event-ID to resume"})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", b)
		fl.Flush()
	}
	wake, cancel, checkpoint, err := open(ctx)
	if err != nil {
		fail(err)
		return
	}
	defer cancel()
	if checkpoint != "" {
		if _, err := fmt.Fprintf(w, "id: %s\nevent: checkpoint\n\n", checkpoint); err != nil {
			return
		}
		fl.Flush()
	}
	if err := drain(); err != nil {
		fail(err)
		return
	}
	tick := time.NewTicker(keepalive)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
		if err := drain(); err != nil {
			fail(err)
			return
		}
	}
}
