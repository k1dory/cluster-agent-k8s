package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"agent-sandbox/internal/kube"
	"agent-sandbox/internal/model"
)

func TestReviewCatalogCannotChangeNetworkBootstrap(t *testing.T) {
	for _, field := range []string{"env", "model"} {
		t.Run(field, func(t *testing.T) {
			s := catalogStack(t)
			// A tenant must not replace the deployment-owned network configuration.
			vars := map[string]string{"GATEWAY_IP": "192.0.2.123"}
			spec := map[string]any{"image": "stable", "env": vars}
			if field == "model" {
				delete(spec, "env")
				spec["model"] = map[string]any{"env": vars}
			}
			resp, raw := call(t, "PUT", s.platform.URL+"/v1/environments/network", "alice-tok", map[string]any{"spec": spec}, nil)
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnprocessableEntity || resp.StatusCode == http.StatusBadRequest {
				return // Either reject the variable or prevent it from reaching privileged init.
			}
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("environment: %d %s", resp.StatusCode, raw)
			}
			if code, _ := putDoc(t, s.platform.URL, "alice-tok", "agents", "network", `{"spec":{"policy":"backend-dev","environment":"network"}}`); code != http.StatusCreated {
				t.Fatalf("agent: %d", code)
			}
			resp, raw = call(t, "POST", s.platform.URL+"/v1/sandboxes", "alice-tok", map[string]any{"name": "network", "owner": "alice", "agent_ref": "network"}, nil)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("sandbox: %d %s", resp.StatusCode, raw)
			}
			var sb model.Sandbox
			if err := json.Unmarshal(raw, &sb); err != nil {
				t.Fatal(err)
			}
			client := fake.NewSimpleClientset()
			rt := &kube.Runtime{Client: client, Cfg: kube.PodConfig{Namespace: "review", GatewayIP: "10.77.77.1", PodFirewall: true}}
			name, err := rt.CreatePod(t.Context(), &sb)
			if err != nil {
				t.Fatal(err)
			}
			pod, err := client.CoreV1().Pods("review").Get(t.Context(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, init := range pod.Spec.InitContainers {
				if init.Name != "netlock" {
					continue
				}
				for _, v := range init.Env {
					if v.Name == "GATEWAY_IP" && v.Value != rt.Cfg.GatewayIP {
						t.Fatalf("tenant-controlled %s reached privileged netlock: GATEWAY_IP=%q; deployment requires %q", field, v.Value, rt.Cfg.GatewayIP)
					}
				}
			}
		})
	}
}

func TestReviewCatalogRejectsImpossibleResources(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"negative_cpu", `{"spec":{"image":"stable","resources":{"cpu_limit":"-1"}}}`},
		{"negative_memory", `{"spec":{"image":"stable","resources":{"memory_request":"-1Gi"}}}`},
		{"zero_volume", `{"spec":{"image":"stable","resources":{"volume_size":"0"}}}`},
		{"request_above_limit", `{"spec":{"image":"stable","resources":{"cpu_request":"4","cpu_limit":"1"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := catalogStack(t)
			code, _ := putDoc(t, s.platform.URL, "alice-tok", "environments", "invalid", tc.body)
			if code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
				t.Fatalf("invalid pod resources must fail before provisioning, got HTTP %d", code)
			}
		})
	}
}
