package httpapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/registrar"
)

// agentOf creates a running sandbox and bootstraps a pod identity for it, returning the
// certificate header a runner would present.
func agentOf(t *testing.T, s *stack, name string) (model.Sandbox, map[string]string) {
	t.Helper()
	api, gw := s.platform.URL, s.gateway.URL
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": name, "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	sb = waitRunning(t, api, "t0k", sb.ID)
	s.tokens["pod-"+name] = registrar.PodInfo{Name: "agent-" + name, SandboxID: sb.ID, Slug: "backend-dev", Tenant: "alice"}
	_, csr, _ := ca.NewCSR("backend-dev")
	resp, body = call(t, "POST", gw+"/bootstrap", "pod-"+name, registrar.BootstrapRequest{CSR: string(csr)}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap: %d %s", resp.StatusCode, body)
	}
	var boot registrar.BootstrapResponse
	_ = json.Unmarshal(body, &boot)
	blk, _ := pem.Decode([]byte(boot.Cert))
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatal(err)
	}
	return sb, map[string]string{identity.HeaderCertDER: base64.StdEncoding.EncodeToString(blk.Bytes)}
}

// fakeRunner answers file requests the way agent-runner does, from an in-memory tree.
func fakeRunner(ctx context.Context, t *testing.T, gw string, hdr map[string]string, files map[string]string) {
	var after int64
	for ctx.Err() == nil {
		resp, body := call(t, "GET", gw+"/agent/fs/requests?after="+jsonInt(after)+"&wait=1s", "", nil, hdr)
		if resp.StatusCode != 200 {
			return
		}
		var evs []model.Event
		_ = json.Unmarshal(body, &evs)
		for _, e := range evs {
			after = e.ID
			var req model.FSRequest
			_ = json.Unmarshal([]byte(e.Data), &req)
			res := model.FSResult{Request: req.ID}
			switch req.Op {
			case model.FSList:
				res.OK = true
				for p := range files {
					if req.Path == "." || strings.HasPrefix(p, req.Path+"/") {
						res.Entries = append(res.Entries, model.FSEntry{Path: p, Type: "file", Size: int64(len(files[p]))})
					}
				}
			case model.FSRead:
				content, ok := files[req.Path]
				if !ok {
					res.Error = "open " + req.Path + ": no such file or directory"
					break
				}
				r2, b2 := call(t, "POST", gw+"/agent/blobs", "", content, hdr)
				var out struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(b2, &out)
				res.OK, res.Blob, res.Size, res.ContentType = r2.StatusCode == 201, out.Name, int64(len(content)), "text/plain"
			case model.FSWrite:
				r2, b2 := call(t, "GET", gw+"/agent/blobs/"+req.Blob, "", nil, hdr)
				if r2.StatusCode != 200 {
					res.Error = "download: " + r2.Status
					break
				}
				files[req.Path] = string(b2)
				res.OK, res.Size = true, int64(len(b2))
			}
			call(t, "POST", gw+"/agent/fs/results", "", res, hdr)
		}
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestConversationAndWorkspaceFiles(t *testing.T) {
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "chat")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	files := map[string]string{"repo/main.go": "package main\n", "repo/README.md": "# shop\n"}
	go fakeRunner(ctx, t, gw, hdr, files)

	// --- files: list, read, write; another tenant sees nothing -----------------------------
	resp, body := call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/files?path=repo", "t0k", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "repo/main.go") || !strings.Contains(string(body), "repo/README.md") {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/files/content?path=/workspace/repo/main.go", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || string(body) != "package main\n" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("read: %d %q %s", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/files/content?path=repo/missing.go", "t0k", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("missing file: %d", resp.StatusCode)
	}
	resp, body = call(t, "PUT", api+"/v1/sandboxes/"+sb.ID+"/files/content?path=uploads/spec.md", "alice-tok", "# spec\n", map[string]string{"Content-Type": "text/markdown"})
	if resp.StatusCode != 200 || files["uploads/spec.md"] != "# spec\n" || !strings.Contains(string(body), `"size":7`) {
		t.Fatalf("write: %d %s files=%v", resp.StatusCode, body, files)
	}
	for _, path := range []string{"/files?path=repo", "/files/content?path=repo/main.go"} {
		if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+sb.ID+path, "bob-tok", nil, nil); resp.StatusCode != 403 {
			t.Fatalf("bob on alice's files %s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/files?path=../../etc&depth=99", "t0k", nil, nil); resp.StatusCode != 400 {
		t.Fatalf("bad depth: %d", resp.StatusCode)
	}
	// Transfer blobs do not linger once collected.
	if _, err := s.orch.Store.DeleteBlobsBefore(context.Background(), "fs/", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	// --- conversation: first message starts a run, the runner picks it up ------------------
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", MessageRequest{Text: "add tests for checkout"}, nil)
	var mr MessageResponse
	_ = json.Unmarshal(body, &mr)
	if resp.StatusCode != 202 || mr.Delivery != "new" || mr.Run == nil {
		t.Fatalf("first message: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, hdr)
	var run model.Run
	_ = json.Unmarshal(body, &run)
	if resp.StatusCode != 200 || run.ID != mr.Run.ID || run.Task != "add tests for checkout" {
		t.Fatalf("next run: %d %s", resp.StatusCode, body)
	}
	// A multipart message with an attachment lands in uploads/ and is announced to the agent.
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("text", "here is the spec")
	fw, _ := mw.CreateFormFile("file", "checkout spec.md")
	fw.Write([]byte("# checkout\n"))
	mw.Close()
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", mp.String(), map[string]string{"Content-Type": mw.FormDataContentType()})
	_ = json.Unmarshal(body, &mr)
	if resp.StatusCode != 202 || mr.Delivery != "input" || len(mr.Files) != 1 || mr.Files[0] != "uploads/checkout_spec.md" || files["uploads/checkout_spec.md"] != "# checkout\n" {
		t.Fatalf("attachment: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/"+run.ID+"/input?wait=2s", "", nil, hdr)
	var inputs []model.Event
	_ = json.Unmarshal(body, &inputs)
	if resp.StatusCode != 200 || len(inputs) != 1 || !strings.Contains(inputs[0].Data, "here is the spec") || !strings.Contains(inputs[0].Data, "/workspace/uploads/checkout_spec.md") {
		t.Fatalf("input with attachment: %d %s", resp.StatusCode, body)
	}
	// The agent answers in stream-json; the conversation view shows turns, not the raw stream.
	stream := `{"type":"system","subtype":"init","session_id":"sess-9"}
{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{}}]},"session_id":"sess-9"}
{"type":"assistant","message":{"content":[{"type":"text","text":"Read the spec; adding tests."}]},"session_id":"sess-9"}
{"type":"result","subtype":"success","num_turns":2,"session_id":"sess-9","usage":{"input_tokens":5,"output_tokens":9}}
`
	if resp, body := call(t, "POST", gw+"/agent/runs/"+run.ID+"/events", "", stream, hdr); resp.StatusCode != 200 {
		t.Fatalf("output: %d %s", resp.StatusCode, body)
	}
	// Close the conversation: the runner sees run.close; the run finishes normally.
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages/close", "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("close: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/"+run.ID+"/input?after="+jsonInt(inputs[0].ID)+"&wait=2s", "", nil, hdr)
	_ = json.Unmarshal(body, &inputs)
	if resp.StatusCode != 200 || len(inputs) != 1 || inputs[0].Type != model.EventRunClose {
		t.Fatalf("close must reach the runner: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "POST", gw+"/agent/runs/"+run.ID+"/finish", "", map[string]int{"exit_code": 0}, hdr); resp.StatusCode != 204 {
		t.Fatalf("finish: %d", resp.StatusCode)
	}
	// The next message continues the session in a new run.
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", MessageRequest{Text: "now the edge cases"}, nil)
	_ = json.Unmarshal(body, &mr)
	if resp.StatusCode != 202 || mr.Delivery != "resumed" || mr.Run.Session != "sess-9" || mr.Run.Mode != model.RunMessage || mr.Run.ResumeOf != run.ID {
		t.Fatalf("follow-up: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", nil, nil)
	var msgs []model.Message
	_ = json.Unmarshal(body, &msgs)
	var roles []string
	for _, m := range msgs {
		roles = append(roles, m.Role)
	}
	if resp.StatusCode != 200 || strings.Join(roles, ",") != "user,user,tool,assistant,system,user" || msgs[3].Text != "Read the spec; adding tests." || resp.Header.Get("X-Next-Cursor") == "" {
		t.Fatalf("conversation: %d %v %s", resp.StatusCode, roles, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/messages", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob reading alice's conversation: %d", resp.StatusCode)
	}
	// The SSE stream replays the same turns and then stays open.
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	req, _ := http.NewRequestWithContext(sctx, "GET", api+"/v1/sandboxes/"+sb.ID+"/messages/stream", nil)
	req.Header.Set("Authorization", "Bearer alice-tok")
	sse, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sse.Body.Close()
	buf := make([]byte, 64<<10)
	n, _ := sse.Body.Read(buf)
	got := string(buf[:n])
	for i := 0; i < 20 && strings.Count(got, "event: ") < 6; i++ {
		n, _ = sse.Body.Read(buf)
		got += string(buf[:n])
	}
	if strings.Count(got, "event: user") != 3 || !strings.Contains(got, "event: assistant") || !strings.Contains(got, "event: tool") {
		t.Fatalf("stream replay:\n%s", got)
	}
}
