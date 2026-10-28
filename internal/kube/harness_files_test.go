package kube

import (
	"context"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"agent-sandbox/internal/model"
)

// The profile's harness files reach the agent container as SANDBOX_HARNESS_FILES, the JSON the
// runner writes them from; a launch without files sets no variable.
func TestHarnessFilesReachTheAgentContainer(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	rt := &Runtime{Client: client, Cfg: PodConfig{Namespace: "files", Image: "agent:default", GatewayIP: "10.77.77.1"}}
	files := map[string]string{".codex/config.toml": "model_provider = \"gateway\"\n", ".claude/settings.json": "{}"}
	sb := &model.Sandbox{ID: "sb_files", Slug: "dev", Tenant: "acme", Launch: &model.Launch{HarnessCommand: "codex exec \"$SANDBOX_TASK\"", HarnessFiles: files}}
	name, err := rt.CreatePod(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ := client.CoreV1().Pods("files").Get(ctx, name, metav1.GetOptions{})
	var got map[string]string
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "SANDBOX_HARNESS_FILES" {
			if err := json.Unmarshal([]byte(e.Value), &got); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(got) != 2 || got[".codex/config.toml"] != files[".codex/config.toml"] || got[".claude/settings.json"] != "{}" {
		t.Fatalf("SANDBOX_HARNESS_FILES: %v", got)
	}

	sb2 := &model.Sandbox{ID: "sb_nofiles", Slug: "dev", Tenant: "acme", Launch: &model.Launch{}}
	name, err = rt.CreatePod(ctx, sb2)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ = client.CoreV1().Pods("files").Get(ctx, name, metav1.GetOptions{})
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "SANDBOX_HARNESS_FILES" {
			t.Fatalf("a launch without files set %s=%q", e.Name, e.Value)
		}
	}
}
