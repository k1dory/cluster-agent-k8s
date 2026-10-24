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
