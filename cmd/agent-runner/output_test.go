package main

import (
	"strings"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
)

// A line over the limit is dropped with a notice and reading goes on, so the writer never blocks;
// CRLF and a last line without a newline read as before (bufio.Scanner's lines).
func TestReadLinesDropsOversizedLinesAndGoesOn(t *testing.T) {
	in := "a\r\n" + strings.Repeat("x", 300) + "\nb\n" + strings.Repeat("y", 200) + "\nlast"
	out := make(chan string, 16)
	readLines(strings.NewReader(in), 100, out)
	close(out)
	var got []string
	for l := range out {
		got = append(got, l)
	}
	want := []string{"a", "[agent-runner] dropped an output line of 300 bytes (limit 100)", "b",
		"[agent-runner] dropped an output line of 200 bytes (limit 100)", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines:\n%q\nwant\n%q", got, want)
	}
	// Exactly at the limit is kept.
	out = make(chan string, 2)
	readLines(strings.NewReader(strings.Repeat("z", 100)+"\n"), 100, out)
	if l := <-out; len(l) != 100 {
		t.Fatalf("a line at the limit: %d bytes", len(l))
	}
}

// stream-json: a message queued during a turn is answered after that turn's result line; the
// agent speaking again stops the idle clock the result started.
func TestIdleClockStopsWhenTheHarnessGoesOn(t *testing.T) {
	// A clock of the test's own: the real one may not move between two lines (it did not, one run
	// in six, under -race), and an idle time of 0 is no evidence either way.
	now := time.Unix(1_000_000, 0)
	chat := newChat(harness.InputStreamJSON, time.Minute)
	chat.now = func() time.Time { return now }
	chat.sawLine(`{"type":"result","session_id":"s"}`)
	if _, waiting := chat.idleFor(); !waiting {
		t.Fatal("a turn end starts the idle clock")
	}
	now = now.Add(3 * time.Second)
	chat.sawLine(`{"type":"system","subtype":"init"}`)
	if idle, waiting := chat.idleFor(); !waiting || idle != 3*time.Second {
		t.Fatalf("a non-turn line does not stop it: %v %v", idle, waiting)
	}
	chat.sawLine(`{"type":"assistant","message":{"content":[{"type":"text","text":"next answer"}]}}`)
	if _, waiting := chat.idleFor(); waiting {
		t.Fatal("the agent answering the queued message stops the idle clock")
	}
}

// A diff too large for an output line keeps its path and sizes, without the texts.
func TestACPDiffsTruncateLargeChanges(t *testing.T) {
	old := "old"
	small := acpDiffs([]acp.ToolCallContent{acp.ToolDiffContent("a.txt", "new", old)})
	if len(small) != 1 || small[0].Truncated || small[0].NewText != "new" || *small[0].OldText != "old" {
		t.Fatalf("small diff: %+v", small)
	}
	big := acpDiffs([]acp.ToolCallContent{acp.ToolDiffContent("big.txt", strings.Repeat("x", maxACPDiffText+1))})
	if len(big) != 1 || !big[0].Truncated || big[0].NewText != "" || big[0].NewSize != maxACPDiffText+1 || big[0].Path != "big.txt" {
		t.Fatalf("large diff: %+v", big[0].Truncated)
	}
}
