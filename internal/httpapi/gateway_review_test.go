package httpapi

import (
	"encoding/json"
	"testing"

	"agent-sandbox/internal/model"
)

// finish used to ignore its decode error: a malformed body recorded the run as exit 0 with
// no usage. It is a 400 now and the run stays as it was until a body that decodes arrives.
func TestReviewFinishRefusesABodyThatDoesNotDecode(t *testing.T) {
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "finish")
	resp, body := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/runs", "t0k", map[string]string{"task": "fail please"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("run: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, hdr)
	var run model.Run
	_ = json.Unmarshal(body, &run)
	if resp.StatusCode != 200 || run.ID == "" {
		t.Fatalf("next: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []string{`{"exit_code": 3`, `{"exit_code": "3"}`, `{"exit":3}`, ``, `[3]`} {
		resp, body := call(t, "POST", gw+"/agent/runs/"+run.ID+"/finish", "", bad, hdr)
		wantErr(t, "finish "+bad, resp, body, 400, CodeBadRequest)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/runs/"+run.ID, "t0k", nil, nil)
	var got model.Run
	_ = json.Unmarshal(body, &got)
	if got.Status != model.RunRunning {
		t.Fatalf("a refused finish changed the run: %s", body)
	}
	if resp, body := call(t, "POST", gw+"/agent/runs/"+run.ID+"/finish", "", `{"exit_code":3}`, hdr); resp.StatusCode != 204 {
		t.Fatalf("finish: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/runs/"+run.ID, "t0k", nil, nil)
	_ = json.Unmarshal(body, &got)
	if got.Status != model.RunFailed || got.ExitCode != 3 {
		t.Fatalf("finished run: %s", body)
	}
}
