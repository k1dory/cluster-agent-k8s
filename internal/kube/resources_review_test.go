package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"agent-sandbox/internal/model"
)

func TestReviewProfileResourcesRemainValidWithDefaults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		launch model.Launch
	}{
		{"request_above_builtin_limits", model.Launch{CPURequest: "4", MemoryRequest: "8Gi"}},
		{"limit_below_builtin_requests", model.Launch{CPULimit: "100m", MemoryLimit: "512Mi"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			rt := &Runtime{Client: client, Cfg: PodConfig{Namespace: "review", Image: "agent:test"}}
			name, err := rt.CreatePod(t.Context(), &model.Sandbox{ID: "resources", Launch: &tc.launch})
			if err != nil {
				t.Fatal(err)
			}
			pod, err := client.CoreV1().Pods("review").Get(t.Context(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			r := pod.Spec.Containers[0].Resources
			for _, resource := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
				req, limit := r.Requests[resource], r.Limits[resource]
				if req.Cmp(limit) > 0 {
					t.Errorf("valid profile produces invalid %s resources after defaults: request=%s limit=%s", resource, req.String(), limit.String())
				}
			}
		})
	}
}
