// Package kube is the Kubernetes implementation of orchestrator.Runtime and registrar.Resolver.
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	"agent-sandbox/internal/model"
)

// Labels placed on agent pods; the Registrar reads them back during bootstrap.
const (
	LabelSandbox = "agent-sandbox.io/sandbox"
	LabelSlug    = "agent-sandbox.io/slug"
	LabelTenant  = "agent-sandbox.io/tenant"
	LabelRole    = "agent-sandbox.io/role"
)

// PodConfig describes how agent pods are built.
type PodConfig struct {
	Namespace          string
	Image              string
	ImagePullPolicy    string
	ServiceAccount     string
	NetworkAttachment  string // Multus NetworkAttachmentDefinition name (namespace/name allowed)
	GatewayIP          string // DNS server and HTTP gateway for the pod
	RegistrarURL       string // reachable WITHOUT a client cert, e.g. https://registrar.sandbox.internal:8443
	APIURL             string // agent-facing API behind mTLS, e.g. https://api.sandbox.internal
	TokenAudience      string
	RuntimeClassName   string // "" = runc, "gvisor" / "kata" later
	StorageClass       string
	VolumeSize         string
	CPURequest         string
	CPULimit           string
	MemoryRequest      string
	MemoryLimit        string
	HarnessCommand     string // run by agent-runner; task in $SANDBOX_TASK and stdin
	Env                map[string]string
	PriorityClassName  string
	TerminationSeconds int64
}

// Runtime drives pods and PVCs.
type Runtime struct {
	Client kubernetes.Interface
	Cfg    PodConfig
}

// NewClient builds a clientset from in-cluster config or a kubeconfig path.
func NewClient(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func pvcName(sb *model.Sandbox) string { return "ws-" + sb.ID }
func podName(sb *model.Sandbox) string { return "agent-" + sb.ID }

func (r *Runtime) labels(sb *model.Sandbox) map[string]string {
	return map[string]string{
		LabelSandbox: sb.ID, LabelSlug: sb.Slug, LabelTenant: sb.Tenant, LabelRole: "agent",
		"app.kubernetes.io/name": "agent-sandbox", "app.kubernetes.io/component": "agent",
	}
}

// EnsureVolume creates the workspace PVC if it does not exist.
func (r *Runtime) EnsureVolume(ctx context.Context, sb *model.Sandbox) error {
	size := r.Cfg.VolumeSize
	if size == "" {
		size = "10Gi"
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName(sb), Namespace: r.Cfg.Namespace, Labels: r.labels(sb)},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)}},
		},
	}
	if r.Cfg.StorageClass != "" {
		pvc.Spec.StorageClassName = ptr.To(r.Cfg.StorageClass)
	}
	_, err := r.Client.CoreV1().PersistentVolumeClaims(r.Cfg.Namespace).Create(ctx, pvc, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// CreatePod builds the hardened agent pod. The pod has a single interface, provided by
// Multus as its default network, so there is no cluster network, no Service, no CoreDNS.
func (r *Runtime) CreatePod(ctx context.Context, sb *model.Sandbox) (string, error) {
	c := r.Cfg
	requests := corev1.ResourceList{}
	limits := corev1.ResourceList{}
	setQ := func(rl corev1.ResourceList, name corev1.ResourceName, v, def string) {
		if v == "" {
			v = def
		}
		if v == "" {
			return
		}
		rl[name] = resource.MustParse(v)
	}
	setQ(requests, corev1.ResourceCPU, c.CPURequest, "250m")
	setQ(requests, corev1.ResourceMemory, c.MemoryRequest, "1Gi")
	setQ(limits, corev1.ResourceCPU, c.CPULimit, "2")
	setQ(limits, corev1.ResourceMemory, c.MemoryLimit, "4Gi")

	env := []corev1.EnvVar{
		{Name: "SANDBOX_ID", Value: sb.ID},
		{Name: "SANDBOX_SLUG", Value: sb.Slug},
		{Name: "SANDBOX_TENANT", Value: sb.Tenant},
		{Name: "SANDBOX_REPO", Value: sb.Repo},
		{Name: "REGISTRAR_URL", Value: c.RegistrarURL},
		{Name: "API_URL", Value: c.APIURL},
		{Name: "CERT_DIR", Value: "/certs"},
		{Name: "HOME", Value: "/workspace/home"},
		{Name: "HARNESS_CMD", Value: c.HarnessCommand},
	}
	for k, v := range c.Env {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}
	secCtx := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Privileged:               ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To[int64](1000),
		RunAsGroup:               ptr.To[int64](1000),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	mounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: "/workspace"},
		{Name: "certs", MountPath: "/certs"},
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "bootstrap-token", MountPath: "/var/run/secrets/tokens", ReadOnly: true},
	}
	audience := c.TokenAudience
	if audience == "" {
		audience = "agent-sandbox"
	}
	pullPolicy := corev1.PullPolicy(c.ImagePullPolicy)
	if pullPolicy == "" {
		pullPolicy = corev1.PullIfNotPresent
	}
	term := c.TerminationSeconds
	if term == 0 {
		term = 30
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: podName(sb), Namespace: c.Namespace, Labels: r.labels(sb),
			Annotations: map[string]string{
				// Multus: use the sandbox VLAN as the pod's ONLY network.
				"v1.multus-cni.io/default-network": c.NetworkAttachment,
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:            c.ServiceAccount,
			AutomountServiceAccountToken:  ptr.To(false),
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: ptr.To(term),
			EnableServiceLinks:            ptr.To(false),
			// No cluster DNS: the gateway is the only resolver and only answers for the allowlist.
			DNSPolicy: corev1.DNSNone,
			DNSConfig: &corev1.PodDNSConfig{Nameservers: []string{c.GatewayIP}, Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr.To("1")}}},
			SecurityContext: &corev1.PodSecurityContext{
				FSGroup: ptr.To[int64](1000), RunAsNonRoot: ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{{
				Name: "agent-init", Image: c.Image, ImagePullPolicy: pullPolicy,
				Command: []string{"/usr/local/bin/agent-init"}, Env: env,
				VolumeMounts: mounts, SecurityContext: secCtx,
			}},
			Containers: []corev1.Container{{
				Name: "agent", Image: c.Image, ImagePullPolicy: pullPolicy,
				Command: []string{"/usr/local/bin/agent-runner"}, Env: env,
				WorkingDir: "/workspace", VolumeMounts: mounts, SecurityContext: secCtx,
				Resources: corev1.ResourceRequirements{Requests: requests, Limits: limits},
			}},
			Volumes: []corev1.Volume{
				{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName(sb)}}},
				{Name: "certs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "bootstrap-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Path: "bootstrap", Audience: audience, ExpirationSeconds: ptr.To[int64](600),
					}}},
				}}},
			},
		},
	}
	if c.RuntimeClassName != "" {
		pod.Spec.RuntimeClassName = ptr.To(c.RuntimeClassName)
	}
	if c.PriorityClassName != "" {
		pod.Spec.PriorityClassName = c.PriorityClassName
	}
	created, err := r.Client.CoreV1().Pods(c.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// Leftover from a crash: remove and let the caller retry.
		_ = r.Client.CoreV1().Pods(c.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		return "", fmt.Errorf("pod %s still exists, deleting; retry wake", pod.Name)
	}
	if err != nil {
		return "", err
	}
	return created.Name, nil
}

// PodStatus reports readiness and IP. Multus publishes the default-network IP as pod.Status.PodIP.
func (r *Runtime) PodStatus(ctx context.Context, sb *model.Sandbox) (bool, string, error) {
	name := sb.PodName
	if name == "" {
		name = podName(sb)
	}
	pod, err := r.Client.CoreV1().Pods(r.Cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, "", errors.New("pod not found")
	}
	if err != nil {
		return false, "", err
	}
	switch pod.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		return false, pod.Status.PodIP, fmt.Errorf("pod %s: %s", name, pod.Status.Phase)
	}
	ip := pod.Status.PodIP
	if ip == "" {
		ip = ipFromNetworkStatus(pod.Annotations["k8s.v1.cni.cncf.io/network-status"])
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true, ip, nil
		}
	}
	return false, ip, nil
}

func ipFromNetworkStatus(raw string) string {
	if raw == "" {
		return ""
	}
	var st []struct {
		IPs     []string `json:"ips"`
		Default bool     `json:"default"`
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return ""
	}
	for _, n := range st {
		if n.Default && len(n.IPs) > 0 {
			return n.IPs[0]
		}
	}
	return ""
}

// DeletePod removes the pod (grace period from config) and waits for nothing: the orchestrator
// treats the identity as retired immediately.
func (r *Runtime) DeletePod(ctx context.Context, sb *model.Sandbox) error {
	name := sb.PodName
	if name == "" {
		name = podName(sb)
	}
	err := r.Client.CoreV1().Pods(r.Cfg.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// DeleteVolume removes the workspace PVC.
func (r *Runtime) DeleteVolume(ctx context.Context, sb *model.Sandbox) error {
	err := r.Client.CoreV1().PersistentVolumeClaims(r.Cfg.Namespace).Delete(ctx, pvcName(sb), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// ParseNetworkRef splits "ns/name" for the NAD reference.
func ParseNetworkRef(ref, defaultNS string) (string, string) {
	if i := strings.Index(ref, "/"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return defaultNS, ref
}
