package kube

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"agent-sandbox/internal/registrar"
)

// Resolver verifies projected ServiceAccount tokens with TokenReview and reads the pod's labels.
type Resolver struct {
	Client    kubernetes.Interface
	Namespace string
	Audience  string
}

const (
	extraPodName = "authentication.kubernetes.io/pod-name"
)

// Resolve implements registrar.Resolver.
func (k *Resolver) Resolve(ctx context.Context, token string) (*registrar.PodInfo, error) {
	tr := &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{k.Audience}}}
	res, err := k.Client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("tokenreview: %w", err)
	}
	if !res.Status.Authenticated {
		return nil, registrar.ErrUnauthorized
	}
	podNames := res.Status.User.Extra[extraPodName]
	if len(podNames) == 0 {
		return nil, fmt.Errorf("%w: token is not bound to a pod", registrar.ErrUnauthorized)
	}
	pod, err := k.Client.CoreV1().Pods(k.Namespace).Get(ctx, podNames[0], metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: pod %s: %v", registrar.ErrUnauthorized, podNames[0], err)
	}
	if pod.Labels[LabelRole] != "agent" {
		return nil, fmt.Errorf("%w: pod %s is not an agent pod", registrar.ErrUnauthorized, pod.Name)
	}
	return &registrar.PodInfo{
		Name: pod.Name, Namespace: pod.Namespace,
		SandboxID: pod.Labels[LabelSandbox], Slug: pod.Labels[LabelSlug], Tenant: pod.Labels[LabelTenant],
	}, nil
}
