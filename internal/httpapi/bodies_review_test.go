package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/orchestrator"
)

// errorOf decodes the error envelope and fails unless the response is one.
func errorOf(t *testing.T, resp *http.Response, body []byte) ErrorBody {
	t.Helper()
	var e ErrorBody
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || json.Unmarshal(body, &e) != nil || e.Code == "" || e.Error == "" {
		t.Fatalf("not the error envelope: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if e.RequestID == "" || e.RequestID != resp.Header.Get("X-Request-Id") {
		t.Fatalf("request_id %q does not match the header %q", e.RequestID, resp.Header.Get("X-Request-Id"))
	}
	return e
}

func wantErr(t *testing.T, what string, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("%s: %d %s, want %d", what, resp.StatusCode, body, status)
	}
	if e := errorOf(t, resp, body); e.Code != code {
		t.Fatalf("%s: code %q, want %q (%s)", what, e.Code, code, body)
	}
}

// multipartBody is a message with a text field and files, under the given boundary.
func multipartBody(t *testing.T, boundary, text string, files ...[2]string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if boundary != "" {
		if err := mw.SetBoundary(boundary); err != nil {
			t.Fatal(err)
		}
	}
	_ = mw.WriteField("text", text)
	for _, f := range files {
		fw, _ := mw.CreateFormFile("file", f[0])
		_, _ = fw.Write([]byte(f[1]))
	}
	_ = mw.Close()
	return mw.FormDataContentType(), buf.Bytes()
}

func postRaw(t *testing.T, url, token, contentType string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// Small JSON bodies are one class: capped at jsonBodyLimit (413 over it, also when the
// idempotency middleware reads the body first) and strict (400 for unknown fields or
// trailing data), on every route of the class.
func TestReviewJSONBodiesAreCappedAndStrict(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "caps", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb struct{ ID string }
	_ = json.Unmarshal(body, &sb)
	big := `{"name":"x","pad":"` + strings.Repeat("a", jsonBodyLimit) + `"}`
	routes := []struct{ method, path string }{
		{"POST", "/v1/sandboxes"},
		{"PATCH", "/v1/sandboxes/" + sb.ID},
		{"POST", "/v1/sandboxes/" + sb.ID + "/runs"},
		{"POST", "/v1/sandboxes/" + sb.ID + "/runs/r1/input"},
		{"POST", "/v1/sandboxes/" + sb.ID + "/messages"},
		{"POST", "/v1/sandboxes/" + sb.ID + "/requests/q1"},
		{"PUT", "/v1/sandboxes/" + sb.ID + "/preview"},
		{"POST", "/v1/sandboxes/" + sb.ID + "/preview/ticket"},
		{"POST", "/v1/rollouts"},
	}
	for _, rt := range routes {
		resp, body := call(t, rt.method, api+rt.path, "t0k", big, nil)
		wantErr(t, rt.method+" "+rt.path+" over the cap", resp, body, 413, CodeTooLarge)
		resp, body = call(t, rt.method, api+rt.path, "t0k", `{"no_such_field":1}`, nil)
		wantErr(t, rt.method+" "+rt.path+" unknown field", resp, body, 400, CodeBadRequest)
		resp, body = call(t, rt.method, api+rt.path, "t0k", `{} {}`, nil)
		wantErr(t, rt.method+" "+rt.path+" trailing data", resp, body, 400, CodeBadRequest)
	}
	// With an Idempotency-Key the middleware reads first: still 413, never a hash of a prefix.
	for _, path := range []string{"/v1/sandboxes", "/v1/sandboxes/" + sb.ID + "/runs", "/v1/sandboxes/" + sb.ID + "/messages"} {
		resp, body := call(t, "POST", api+path, "t0k", big, map[string]string{"Idempotency-Key": "k-" + path})
		wantErr(t, "keyed "+path+" over the cap", resp, body, 413, CodeTooLarge)
	}
}

// Documents and bundles are capped too, with 413 rather than a parse error on a cut body.
func TestReviewDocumentAndBundleBodiesAreCapped(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	doc := `{"kind":"EnvironmentProfile","name":"py","spec":{"image":"stable","env":{"PAD":"` + strings.Repeat("a", documentBodyLimit) + `"}}}`
	resp, body := call(t, "PUT", api+"/v1/environments/py", "alice-tok", doc, nil)
	wantErr(t, "document over the cap", resp, body, 413, CodeTooLarge)
	bundle := `[` + strings.Repeat(`{"kind":"EnvironmentProfile","name":"py","spec":{"image":"stable"}},`, bundleBodyLimit/60) + `{}]`
	for _, path := range []string{"/v1/plan", "/v1/apply"} {
		resp, body := call(t, "POST", api+path, "alice-tok", bundle, nil)
		wantErr(t, path+" over the cap", resp, body, 413, CodeTooLarge)
	}
	resp, body = call(t, "POST", api+"/v1/rollback", "alice-tok", `{"apply":"a","bogus":true}`, nil)
	wantErr(t, "rollback unknown field", resp, body, 400, CodeBadRequest)
}

// A keyed multipart message over 1 MiB used to be cut by the idempotency middleware and
// fail with 400 "unexpected EOF"; it is accepted now, and the multipart class has its own caps.
func TestReviewMultipartMessagesHaveTheirOwnCap(t *testing.T) {
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "upload")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	files := map[string]string{}
	go fakeRunner(ctx, t, gw, hdr, files)

	big := strings.Repeat("x", 2<<20)
	ct, mp := multipartBody(t, "", "the big one", [2]string{"big.bin", big})
	resp, body := postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct, bytes.NewReader(mp), map[string]string{"Idempotency-Key": "upload-1"})
	if resp.StatusCode != 202 || files["uploads/big.bin"] != big {
		t.Fatalf("keyed 2 MiB upload: %d %s (stored %d bytes)", resp.StatusCode, body, len(files["uploads/big.bin"]))
	}

	var many [][2]string
	for i := 0; i <= MaxUploadFiles; i++ {
		many = append(many, [2]string{fmt.Sprintf("f%d.txt", i), "x"})
	}
	ct, mp = multipartBody(t, "", "too many", many...)
	resp, body = postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct, bytes.NewReader(mp), nil)
	wantErr(t, "too many files", resp, body, 413, CodeTooLarge)

	ct, mp = multipartBody(t, "", "one file over its cap", [2]string{"huge.bin", strings.Repeat("x", orchestrator.MaxFileBytes+1)})
	resp, body = postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct, bytes.NewReader(mp), map[string]string{"Idempotency-Key": "upload-2"})
	wantErr(t, "file over its cap", resp, body, 413, CodeTooLarge)

	if testing.Short() {
		return
	}
	// The whole body is capped: a stream longer than every file at its cap is cut off at the
	// cap with 413, before the parser can spill it all to disk.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		fw, _ := mw.CreateFormFile("file", "endless.bin")
		chunk := bytes.Repeat([]byte("y"), 1<<20)
		for i := int64(0); i <= multipartBodyLimit>>20+1; i++ {
			if _, err := fw.Write(chunk); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.CloseWithError(mw.Close())
	}()
	resp, body = postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", mw.FormDataContentType(), pr, nil)
	pr.Close()
	wantErr(t, "multipart over the total cap", resp, body, 413, CodeTooLarge)
}

// A retried multipart upload has a new random boundary; the idempotency hash is over what the
// form carries, so the retry replays instead of answering 422, and other content still is 422.
func TestReviewMultipartRetryWithAnotherBoundaryReplays(t *testing.T) {
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "retry")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fakeRunner(ctx, t, gw, hdr, map[string]string{})

	key := map[string]string{"Idempotency-Key": "same-upload"}
	ct1, b1 := multipartBody(t, "boundary-one-1111", "see attached", [2]string{"a.txt", "alpha"}, [2]string{"b.txt", "beta"})
	resp1, body1 := postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct1, bytes.NewReader(b1), key)
	if resp1.StatusCode != 202 {
		t.Fatalf("first upload: %d %s", resp1.StatusCode, body1)
	}
	ct2, b2 := multipartBody(t, "boundary-two-2222", "see attached", [2]string{"a.txt", "alpha"}, [2]string{"b.txt", "beta"})
	if bytes.Equal(b1, b2) {
		t.Fatal("the two bodies must differ in their bytes")
	}
	resp2, body2 := postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct2, bytes.NewReader(b2), key)
	if resp2.StatusCode != 202 || resp2.Header.Get("Idempotency-Replayed") != "true" || !bytes.Equal(body1, body2) {
		t.Fatalf("retry with another boundary: %d replayed=%q %s", resp2.StatusCode, resp2.Header.Get("Idempotency-Replayed"), body2)
	}
	// The files in another order, another content or another name are another request.
	for _, files := range [][][2]string{
		{{"b.txt", "beta"}, {"a.txt", "alpha"}},
		{{"a.txt", "alpha!"}, {"b.txt", "beta"}},
		{{"a2.txt", "alpha"}, {"b.txt", "beta"}},
	} {
		ct, b := multipartBody(t, "", "see attached", files...)
		resp, body := postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", ct, bytes.NewReader(b), key)
		wantErr(t, fmt.Sprintf("other upload %v under the key", files), resp, body, 422, CodeInvalid)
	}
}

// Uploads that spill to temporary files leave none behind: auth hands the handlers a copy of
// the request, so net/http's own cleanup never sees the parsed form. Covered: a keyed upload,
// its replay, an unkeyed upload and a rejected one (too many files).
func TestReviewMultipartTemporaryFilesAreRemoved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "spill")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fakeRunner(ctx, t, gw, hdr, map[string]string{})

	big := strings.Repeat("s", multipartMemory+(1<<20)) // over what is kept in memory
	url := api + "/v1/sandboxes/" + sb.ID + "/messages"
	key := map[string]string{"Idempotency-Key": "spill-1"}
	var many [][2]string
	for i := 0; i <= MaxUploadFiles; i++ {
		many = append(many, [2]string{fmt.Sprintf("f%d.bin", i), big[:1<<20]})
	}
	many[0][1] = big
	for _, c := range []struct {
		what  string
		hdr   map[string]string
		files [][2]string
		want  int
	}{
		{"keyed upload", key, [][2]string{{"big.bin", big}}, 202},
		{"replay", key, [][2]string{{"big.bin", big}}, 202},
		{"unkeyed upload", nil, [][2]string{{"big.bin", big}}, 202},
		{"rejected upload", map[string]string{"Idempotency-Key": "spill-2"}, many, 413},
	} {
		ct, b := multipartBody(t, "", "upload", c.files...)
		resp, body := postRaw(t, url, "alice-tok", ct, bytes.NewReader(b), c.hdr)
		if resp.StatusCode != c.want {
			t.Fatalf("%s: %d %s", c.what, resp.StatusCode, body)
		}
		left, _ := filepath.Glob(filepath.Join(tmp, "multipart-*"))
		if len(left) > 0 {
			t.Fatalf("%s left temporary files: %v", c.what, left)
		}
	}
}

// Only the messages route reads multipart. The other idempotent routes take JSON: a keyed
// multipart body there is held to the JSON cap and never parsed, so a large file part cannot
// spill to disk on a route that would refuse it anyway.
func TestReviewMultipartIsParsedOnlyOnTheMessagesRoute(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	s := newStack(t)
	api := s.platform.URL
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "nomp", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb struct{ ID string }
	_ = json.Unmarshal(body, &sb)
	big := strings.Repeat("s", multipartMemory+(1<<20))
	for i, path := range []string{"/v1/sandboxes", "/v1/sandboxes/" + sb.ID + "/runs", "/v1/sandboxes/" + sb.ID + "/requests/q1"} {
		for _, file := range []string{big, "small"} {
			ct, b := multipartBody(t, "", "x", [2]string{"f.bin", file})
			resp, body := postRaw(t, api+path, "t0k", ct, bytes.NewReader(b), map[string]string{"Idempotency-Key": fmt.Sprintf("mp-%d-%d", i, len(file))})
			if resp.StatusCode != 413 && resp.StatusCode != 400 {
				t.Fatalf("%s multipart: %d %s", path, resp.StatusCode, body)
			}
			if left, _ := filepath.Glob(filepath.Join(tmp, "multipart-*")); len(left) > 0 {
				t.Fatalf("%s left temporary files: %v", path, left)
			}
		}
	}
}

// The whole-body cap holds after the closing boundary too: ParseMultipartForm stops there, so a
// valid message followed by an endless epilogue is read to the cap and refused, keyed or not,
// before any file is written or the message sent.
func TestReviewMultipartEpilogueCountsAgainstTheCap(t *testing.T) {
	if testing.Short() {
		t.Skip("streams more than the multipart cap")
	}
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "epilogue")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	files := map[string]string{}
	go fakeRunner(ctx, t, gw, hdr, files)
	for _, keyed := range []bool{false, true} {
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		go func() {
			_ = mw.WriteField("text", "hello")
			fw, _ := mw.CreateFormFile("file", "small.txt")
			_, _ = fw.Write([]byte("small"))
			_ = mw.Close()
			junk := bytes.Repeat([]byte("e"), 1<<20)
			for i := int64(0); i <= multipartBodyLimit>>20+1; i++ {
				if _, err := pw.Write(junk); err != nil {
					pw.CloseWithError(err)
					return
				}
			}
			pw.Close()
		}()
		h := map[string]string{}
		if keyed {
			h["Idempotency-Key"] = "epilogue"
		}
		resp, body := postRaw(t, api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", mw.FormDataContentType(), pr, h)
		pr.Close()
		wantErr(t, fmt.Sprintf("keyed=%v epilogue over the cap", keyed), resp, body, 413, CodeTooLarge)
		if len(files) > 0 {
			t.Fatalf("keyed=%v: a file was written before the body was refused: %v", keyed, files)
		}
	}
}

// Over the cap, the answer comes at once and the connection closes: a chunked client that
// sends cap+1 bytes and then stalls is not waited for. MaxBytesReader can only tell net/http
// so through the server's own ResponseWriter, not through the middleware's wrappers.
func TestReviewOverTheCapAnswersWithoutWaitingForTheRest(t *testing.T) {
	s := newStack(t)
	addr := strings.TrimPrefix(s.platform.URL, "http://")
	for _, c := range []struct{ what, path string }{
		{"strict JSON (decodeStrict)", "/v1/rollouts"},
		{"keyed JSON (idempotency hash)", "/v1/sandboxes"},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0k\r\nIdempotency-Key: stall\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n", c.path)
		fmt.Fprintf(conn, "%x\r\n%s\r\n", len(`{"version":"`), `{"version":"`) // valid JSON up to the cap
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for sent := 0; sent <= jsonBodyLimit+len(chunk); sent += len(chunk) {
			fmt.Fprintf(conn, "%x\r\n%s\r\n", len(chunk), chunk)
		}
		// No terminating chunk: the client stalls here.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			t.Fatalf("%s: no answer while the client stalls: %v", c.what, err)
		}
		resp.Body.Close()
		conn.Close()
		if resp.StatusCode != 413 {
			t.Fatalf("%s: %d", c.what, resp.StatusCode)
		}
	}
}
