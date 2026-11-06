package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sseFrame is one server-sent event: its id, event name and data (multi-line data joined).
type sseFrame struct {
	ID, Event, Data string
}

// readSSE calls fn for every complete frame of r until fn returns false or r ends. Comment
// lines (the keepalive) are skipped.
func readSSE(r io.Reader, fn func(sseFrame) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var f sseFrame
	var data []string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			// A frame with an id but no data (a checkpoint) is dispatched too: its id is a
			// cursor to keep, as an EventSource keeps it.
			if data != nil || f.ID != "" || f.Event != "" {
				f.Data = strings.Join(data, "\n")
				if !fn(f) {
					return nil
				}
			}
			f, data = sseFrame{}, nil
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			f.ID = value
		case "event":
			f.Event = value
		case "data":
			data = append(data, value)
		}
	}
	return sc.Err()
}

// streamError reports whether f is the frame sandboxd ends a stream with when it cannot read
// the event log, and its message. Its body is an error, not an event or a message: decoded as
// one it would carry id 0, and resuming from 0 replays the whole history.
func streamError(f sseFrame) (string, bool) {
	if f.Event != "error" {
		return "", false
	}
	var b struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(f.Data), &b) != nil || b.Error == "" {
		return f.Data, true
	}
	return b.Error, true
}

// followRetry and followRetryMax bound the wait before a stream is reconnected after the
// server ended it with an error: doubling, reset by the next frame that arrives.
var (
	followRetry    = time.Second
	followRetryMax = 30 * time.Second
)

// transientStatus: an answer worth retrying with the same cursor (the server, a proxy in front
// of it or its database unavailable, or a rate limit). A 4xx otherwise is final: retrying a
// refused token or a missing sandbox only repeats the refusal.
func transientStatus(code int) bool {
	return code >= 500 || code == http.StatusTooManyRequests
}

type backoff struct{ next time.Duration }

func (b *backoff) reset() { b.next = 0 }

// wait sleeps the next interval (false when ctx ended first).
func (b *backoff) wait(ctx context.Context) bool {
	if b.next == 0 {
		b.next = followRetry
	}
	t := time.NewTimer(b.next)
	defer t.Stop()
	b.next = min(2*b.next, followRetryMax)
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// frameCursor is what a reconnect hands back as Last-Event-ID: the frame's own id as the
// server wrote it (a bounded trace adds its replay boundary to the event id), else the id of
// the event or message in it.
func frameCursor(f sseFrame, id int64) string {
	if f.ID != "" {
		return f.ID
	}
	return strconv.FormatInt(id, 10)
}

// checkpoint reports whether f is a cursor-only frame (`event: checkpoint`): sandboxd sends
// one first on a bounded trace, so a resume keeps its replay boundary even when no event has
// arrived. It is never printed.
func checkpoint(f sseFrame) bool { return f.Event == "checkpoint" }
