package kube

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"agent-sandbox/internal/model"
)

func TestReviewCreatePodWaitsForPreviousIncarnation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sb := &model.Sandbox{ID: "sb_review", Slug: "dev", Tenant: "acme", AgentVersion: "agent:v2"}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName(sb), Namespace: "review"}}
	client := fake.NewSimpleClientset(old)
	deletes, reads := 0, 0
	client.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		deletes++
		return true, nil, nil // accepted; still present during graceful termination
	})
	client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		reads++
		if reads == 1 {
			return true, old.DeepCopy(), nil
		}
		if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), old.Namespace, old.Name); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, old.Name)
	})
	rt := &Runtime{Client: client, Cfg: PodConfig{Namespace: "review", Image: "agent:v2"}}
	name, err := rt.CreatePod(ctx, sb)
	if err != nil {
		t.Fatalf("graceful deletion must not break replacement: %v", err)
	}
	if name != old.Name || deletes != 1 || reads < 2 {
		t.Fatalf("did not observe the terminating pod before replacement: name=%q deletes=%d reads=%d", name, deletes, reads)
	}
}

func TestReviewGatewayTrustAndNetworkLockWiring(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	rt := &Runtime{Client: client, Cfg: PodConfig{Namespace: "review", Image: "agent:test", GatewayIP: "10.77.77.1", PodFirewall: true, GatewayCAConfigMap: "review-ca"}}
	if err := rt.PublishGatewayCA(ctx, []byte("test-root")); err != nil {
		t.Fatal(err)
	}
	cm, err := client.CoreV1().ConfigMaps("review").Get(ctx, "review-ca", metav1.GetOptions{})
	if err != nil || cm.Data[GatewayCAKey] != "test-root" {
		t.Fatalf("gateway root not published: cm=%v err=%v", cm, err)
	}
	name, err := rt.CreatePod(ctx, &model.Sandbox{ID: "sb_review", Slug: "dev", Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	pod, err := client.CoreV1().Pods("review").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.InitContainers) != 2 || pod.Spec.InitContainers[0].Name != "netlock" || pod.Spec.InitContainers[1].Name != "agent-init" {
		t.Fatalf("network lock must precede certificate bootstrap: %+v", pod.Spec.InitContainers)
	}
	main := pod.Spec.Containers[0].SecurityContext
	if main.RunAsUser == nil || *main.RunAsUser == 0 || len(main.Capabilities.Add) != 0 {
		t.Fatal("the agent must not inherit the network init container's privileges")
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == "gateway-ca" {
			if v.ConfigMap == nil || v.ConfigMap.Name != "review-ca" {
				t.Error("pod does not mount the published gateway root")
			}
			return
		}
	}
	t.Fatal("gateway trust volume is missing")
}

func TestLaunchShapesThePod(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	rt := &Runtime{Client: client, Cfg: PodConfig{Namespace: "review", Image: "agent:default", GatewayIP: "10.77.77.1",
		HarnessCommand: "claude -p \"$SANDBOX_TASK\"", CPULimit: "2", MemoryLimit: "4Gi", VolumeSize: "10Gi",
		Env: map[string]string{"ANTHROPIC_BASE_URL": "https://api.anthropic.com", "KEEP": "1"}}}
	sb := &model.Sandbox{ID: "sb_launch", Slug: "dev", Tenant: "acme", AgentVersion: "agent:py-1.2", AgentRef: "backend", AgentRevision: 3,
		EnvironmentRef: "py", EnvironmentRevision: 2, Launch: &model.Launch{
			Image: "agent:py-1.2", HarnessCommand: "codex exec \"$SANDBOX_TASK\" --json", Model: "claude-opus-5-5", Instructions: "Be brief.",
			// GATEWAY_IP, SANDBOX_ID and KEEP must not win: platform and operator names stay theirs.
			Env:      map[string]string{"PIP_INDEX_URL": "https://pypi.example.com", "GATEWAY_IP": "192.0.2.9", "SANDBOX_ID": "forged", "KEEP": "2"},
			CPULimit: "3", MemoryRequest: "2Gi", VolumeSize: "20Gi", RuntimeClass: "gvisor"}}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	pvc, _ := client.CoreV1().PersistentVolumeClaims("review").Get(ctx, pvcName(sb), metav1.GetOptions{})
	if got := pvc.Spec.Resources.Requests.Storage().String(); got != "20Gi" {
		t.Fatalf("volume size from the launch: %s", got)
	}
	name, err := rt.CreatePod(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ := client.CoreV1().Pods("review").Get(ctx, name, metav1.GetOptions{})
	c := pod.Spec.Containers[0]
	env := map[string]string{}
	for _, e := range c.Env {
		env[e.Name] = e.Value
	}
	switch {
	case c.Image != "agent:py-1.2":
		t.Fatalf("image: %s", c.Image)
	case env["HARNESS_CMD"] != "codex exec \"$SANDBOX_TASK\" --json":
		t.Fatalf("harness: %q", env["HARNESS_CMD"])
	case env["ANTHROPIC_MODEL"] != "claude-opus-5-5" || env["SANDBOX_MODEL"] != "claude-opus-5-5" || env["SANDBOX_INSTRUCTIONS"] != "Be brief." || env["PIP_INDEX_URL"] == "" || env["KEEP"] != "1" || env["ANTHROPIC_BASE_URL"] == "":
		t.Fatalf("env merge: %v", env)
	case env["GATEWAY_IP"] != "10.77.77.1" || env["SANDBOX_ID"] != "sb_launch":
		t.Fatalf("profile env shadowed a platform name: %v", env)
	case env["SANDBOX_AGENT_REF"] != "backend" || env["SANDBOX_AGENT_REVISION"] != "3" || env["SANDBOX_ENVIRONMENT_REVISION"] != "2":
		t.Fatalf("revision env: %v", env)
	case c.Resources.Limits.Cpu().String() != "3" || c.Resources.Limits.Memory().String() != "4Gi" || c.Resources.Requests.Memory().String() != "2Gi":
		t.Fatalf("resources: %+v", c.Resources)
	case pod.Spec.RuntimeClassName == nil || *pod.Spec.RuntimeClassName != "gvisor":
		t.Fatal("runtime class from the launch")
	}
	for _, init := range pod.Spec.InitContainers {
		for _, e := range init.Env {
			if e.Name == "PIP_INDEX_URL" || e.Name == "GATEWAY_IP" && e.Value != "10.77.77.1" {
				t.Fatalf("init container %s got profile env %s=%s", init.Name, e.Name, e.Value)
			}
		}
	}
	// A profile request above the operator's limit raises the limit rather than making an
	// invalid pod.
	sb.Launch.Env, sb.Launch.CPULimit, sb.Launch.CPURequest, sb.Instance = nil, "", "4", 2
	name, err = rt.CreatePod(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ = client.CoreV1().Pods("review").Get(ctx, name, metav1.GetOptions{})
	if res := pod.Spec.Containers[0].Resources; res.Requests.Cpu().String() != "4" || res.Limits.Cpu().String() != "4" {
		t.Fatalf("request above limit: %+v", res)
	}
}

// The names of the pod and the workspace volume are what the API server accepts: a sandbox
// id carries an underscore (sb_…), which a DNS subdomain may not; the fake client never
// validated them, the first real cluster refused the volume.
func TestPodAndVolumeNamesAreValidObjectNames(t *testing.T) {
	sb := &model.Sandbox{ID: "sb_85ac4a23c9ae"}
	for _, name := range []string{podName(sb), pvcName(sb)} {
		if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
			t.Errorf("%q: %v", name, errs)
		}
	}
	if podName(sb) != "agent-sb-85ac4a23c9ae" || pvcName(sb) != "ws-sb-85ac4a23c9ae" {
		t.Errorf("names: %s %s", podName(sb), pvcName(sb))
	}
}
