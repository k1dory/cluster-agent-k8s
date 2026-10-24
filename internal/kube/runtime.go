// Package kube is the Kubernetes implementation of orchestrator.Runtime and registrar.Resolver.
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
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
	Namespace         string
	Image             string
	ImagePullPolicy   string
	ServiceAccount    string
	NetworkAttachment string // Multus NetworkAttachmentDefinition name (namespace/name allowed)
	GatewayIP         string // DNS server and HTTP gateway for the pod
	RegistrarURL      string // reachable WITHOUT a client cert, e.g. https://registrar.sandbox.internal:8443
	APIURL            string // agent-facing API behind mTLS, e.g. https://api.sandbox.internal
	TokenAudience     string
	RuntimeClassName  string // "" = runc, "gvisor" / "kata" later
	StorageClass      string
	VolumeSize        string
	CPURequest        string
	CPULimit          string
	MemoryRequest     string
	MemoryLimit       string
	HarnessCommand    string // run by agent-runner; task in $SANDBOX_TASK and stdin
	// HarnessResumeCommand continues an interrupted run: $SANDBOX_SESSION is the harness's
	// conversation id, $SANDBOX_RESUME_PROMPT the text to continue with, $SANDBOX_RESUME_OF the
	// interrupted run. Empty: the task is simply run again.
	HarnessResumeCommand string
	ResumePrompt         string
	HarnessInput         string // text | stream-json (see model.Launch)
	ChatIdleSeconds      int
	// Env is the operator's environment (deployment configuration): trusted, set on every
	// container of the pod. UserEnv is the sandbox's profile environment: it reaches the agent
	// container only, and never under a platform name (model.PlatformEnv) or one Env sets.
	Env     map[string]string
	UserEnv map[string]string
	// Model and Instructions come from the sandbox's launch and are exported by the platform
	// as SANDBOX_MODEL / ANTHROPIC_MODEL and SANDBOX_INSTRUCTIONS.
	Model              string
	Instructions       string
	PriorityClassName  string
	TerminationSeconds int64
	// PodFirewall adds an init container (NET_ADMIN, dropped afterwards) that installs nftables
	// rules inside the pod's network namespace: egress only to the gateway on 53/443/8443. It is
	// what keeps pods on different nodes of the shared VLAN from reaching each other directly.
	PodFirewall bool
	// GatewayCAConfigMap names the ConfigMap (key gateway-ca.crt) sandboxd keeps up to date with
	// the gateway's root certificate, mounted into pods so the init container can trust the
	// registrar before it has bootstrapped. "" disables the mount.
	GatewayCAConfigMap string
}

// GatewayCAKey is the key of the gateway root inside GatewayCAConfigMap.
const GatewayCAKey = "gateway-ca.crt"

// PublishGatewayCA writes the gateway root into the ConfigMap pods mount (created if missing).
func (r *Runtime) PublishGatewayCA(ctx context.Context, pemBytes []byte) error {
	if r.Cfg.GatewayCAConfigMap == "" {
		return nil
	}
	cms := r.Client.CoreV1().ConfigMaps(r.Cfg.Namespace)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: r.Cfg.GatewayCAConfigMap, Namespace: r.Cfg.Namespace,
		Labels: map[string]string{"app.kubernetes.io/name": "agent-sandbox"}}, Data: map[string]string{GatewayCAKey: string(pemBytes)}}
	_, err := cms.Create(ctx, cm, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

// ImageFor is the agent image a sandbox's pod runs: its AgentVersion (an image reference set
// by the orchestrator from the version catalogue) or the configured default.
func (c PodConfig) ImageFor(sb *model.Sandbox) string {
	if sb.AgentVersion != "" {
		return sb.AgentVersion
	}
	return c.Image
}

// effective merges the sandbox's launch (its environment profile, rendered at creation) over
// the configured defaults: every launch parameter the profile sets wins, the rest stays global.
// The profile's variables are kept apart (UserEnv) so they can be confined to the agent container.
func (c PodConfig) effective(sb *model.Sandbox) PodConfig {
	e := c
	e.Image = c.ImageFor(sb)
	e.UserEnv = nil
	l := sb.Launch
	if l == nil {
		l = &model.Launch{}
	}
	pick := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	pick(&e.HarnessCommand, l.HarnessCommand)
	pick(&e.HarnessResumeCommand, l.HarnessResumeCommand)
	pick(&e.ResumePrompt, l.ResumePrompt)
	pick(&e.HarnessInput, l.HarnessInput)
	if l.ChatIdle > 0 {
		e.ChatIdleSeconds = l.ChatIdle
	}
	pick(&e.CPURequest, l.CPURequest)
	pick(&e.CPULimit, l.CPULimit)
	pick(&e.MemoryRequest, l.MemoryRequest)
	pick(&e.MemoryLimit, l.MemoryLimit)
	pick(&e.VolumeSize, l.VolumeSize)
	pick(&e.RuntimeClassName, l.RuntimeClass)
	pick(&e.Model, l.Model)
	pick(&e.Instructions, l.Instructions)
	e.UserEnv = l.Env
	e.CPURequest, e.CPULimit = reconcile(e.CPURequest, e.CPULimit, l.CPURequest, l.CPULimit, defaultCPURequest, defaultCPULimit)
	e.MemoryRequest, e.MemoryLimit = reconcile(e.MemoryRequest, e.MemoryLimit, l.MemoryRequest, l.MemoryLimit, defaultMemoryRequest, defaultMemoryLimit)
	return e
}

// Built-in pod resources when neither the operator nor the profile sets one.
const (
	defaultCPURequest    = "250m"
	defaultCPULimit      = "2"
	defaultMemoryRequest = "1Gi"
	defaultMemoryLimit   = "4Gi"
)

// reconcile fills the request/limit pair with the defaults, then makes it a valid pod: a
// profile value is what the author asked for, so when the pair contradicts, the side the
// profile did not set moves (a request above a default limit raises the limit; a limit below
// a default request lowers the request). Both profile sides were validated together by the
// catalogue; a contradiction the operator configured resolves by raising the limit.
func reconcile(req, lim, profileReq, profileLim, defReq, defLim string) (string, string) {
	if req == "" {
		req = defReq
	}
	if lim == "" {
		lim = defLim
	}
	rq, err1 := resource.ParseQuantity(req)
	lq, err2 := resource.ParseQuantity(lim)
	if err1 != nil || err2 != nil || rq.Cmp(lq) <= 0 {
		return req, lim
	}
	if profileLim != "" && profileReq == "" {
		return lim, lim
	}
	return req, req
}

// Annotation carrying the agent image on the pod, so `kubectl get pod -o yaml` tells the version.
const AnnotationVersion = "agent-sandbox.io/agent-version"

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
	size := r.Cfg.effective(sb).VolumeSize
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
	c := r.Cfg.effective(sb)
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
	// Defaults and request/limit consistency were settled in effective().
	setQ(requests, corev1.ResourceCPU, c.CPURequest, defaultCPURequest)
	setQ(requests, corev1.ResourceMemory, c.MemoryRequest, defaultMemoryRequest)
	setQ(limits, corev1.ResourceCPU, c.CPULimit, defaultCPULimit)
	setQ(limits, corev1.ResourceMemory, c.MemoryLimit, defaultMemoryLimit)

	env := []corev1.EnvVar{
		{Name: "SANDBOX_ID", Value: sb.ID},
		{Name: "SANDBOX_SLUG", Value: sb.Slug},
		{Name: "SANDBOX_TENANT", Value: sb.Tenant},
		{Name: "SANDBOX_REPO", Value: sb.Repo},
		{Name: "REGISTRAR_URL", Value: c.RegistrarURL},
		{Name: "API_URL", Value: c.APIURL},
		{Name: "CERT_DIR", Value: "/certs"},
		{Name: "HOME", Value: "/workspace/home"},
		{Name: "GATEWAY_IP", Value: c.GatewayIP},
		{Name: "HARNESS_CMD", Value: c.HarnessCommand},
		{Name: "HARNESS_RESUME_CMD", Value: c.HarnessResumeCommand},
		{Name: "SANDBOX_RESUME_PROMPT", Value: c.ResumePrompt},
		{Name: "HARNESS_INPUT", Value: c.HarnessInput},
		{Name: "HARNESS_CHAT_IDLE", Value: strconv.Itoa(c.ChatIdleSeconds)},
		{Name: "SANDBOX_AGENT_VERSION", Value: c.Image},
		{Name: "SANDBOX_ENV_VERSION", Value: sb.EnvVersion},
		{Name: "SANDBOX_AGENT_REF", Value: sb.AgentRef},
		{Name: "SANDBOX_AGENT_REVISION", Value: strconv.Itoa(sb.AgentRevision)},
		{Name: "SANDBOX_ENVIRONMENT_REF", Value: sb.EnvironmentRef},
		{Name: "SANDBOX_ENVIRONMENT_REVISION", Value: strconv.Itoa(sb.EnvironmentRevision)},
	}
	if c.Model != "" {
		env = append(env, corev1.EnvVar{Name: "SANDBOX_MODEL", Value: c.Model}, corev1.EnvVar{Name: "ANTHROPIC_MODEL", Value: c.Model})
	}
	if c.Instructions != "" {
		env = append(env, corev1.EnvVar{Name: "SANDBOX_INSTRUCTIONS", Value: c.Instructions})
	}
	image := c.Image
	env = append(env, sortedEnv(c.Env, nil)...)
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
	if c.GatewayCAConfigMap != "" {
		mounts = append(mounts, corev1.VolumeMount{Name: "gateway-ca", MountPath: "/etc/sandbox/gateway-ca", ReadOnly: true})
		env = append(env, corev1.EnvVar{Name: "GATEWAY_CA_FILE", Value: "/etc/sandbox/gateway-ca/" + GatewayCAKey})
	}
	// env is the platform's: it is all the init containers (network lock, bootstrap) see. The
	// agent container adds the profile's variables, which can neither shadow a platform name
	// nor the operator's.
	agentEnv := append(append([]corev1.EnvVar(nil), env...), sortedEnv(c.UserEnv, env)...)
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
				AnnotationVersion:                  image,
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
			InitContainers: initContainers(c, image, pullPolicy, env, mounts, secCtx),
			Containers: []corev1.Container{{
				Name: "agent", Image: image, ImagePullPolicy: pullPolicy,
				Command: []string{"/usr/local/bin/agent-runner"}, Env: agentEnv,
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
	if c.GatewayCAConfigMap != "" {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "gateway-ca", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: c.GatewayCAConfigMap}, Optional: ptr.To(true)}}})
	}
	if c.RuntimeClassName != "" {
		pod.Spec.RuntimeClassName = ptr.To(c.RuntimeClassName)
	}
	if c.PriorityClassName != "" {
		pod.Spec.PriorityClassName = c.PriorityClassName
	}
	created, err := r.Client.CoreV1().Pods(c.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// The previous incarnation is still terminating (graceful deletion is asynchronous) or
		// was left behind by a crash: make sure it is being deleted, wait for it to go, create.
		if err := r.deleteAndWait(ctx, pod.Name); err != nil {
			return "", fmt.Errorf("previous pod %s: %w", pod.Name, err)
		}
		created, err = r.Client.CoreV1().Pods(c.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	}
	if err != nil {
		return "", err
	}
	return created.Name, nil
}

// sortedEnv renders vars in name order, skipping platform names and names already in taken.
func sortedEnv(vars map[string]string, taken []corev1.EnvVar) []corev1.EnvVar {
	used := map[string]bool{}
	for _, e := range taken {
		used[e.Name] = true
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		if taken != nil && (used[k] || model.PlatformEnv(k)) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]corev1.EnvVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, corev1.EnvVar{Name: k, Value: vars[k]})
	}
	return out
}

// initContainers builds the pod's init sequence: the optional network lock (needs NET_ADMIN,
// which the main container does not have, so the agent cannot undo it), then agent-init.
func initContainers(c PodConfig, image string, pull corev1.PullPolicy, env []corev1.EnvVar, mounts []corev1.VolumeMount, secCtx *corev1.SecurityContext) []corev1.Container {
	var out []corev1.Container
	if c.PodFirewall {
		fw := *secCtx
		fw.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"}}
		fw.RunAsNonRoot, fw.RunAsUser, fw.RunAsGroup = ptr.To(false), ptr.To[int64](0), ptr.To[int64](0)
		out = append(out, corev1.Container{
			Name: "netlock", Image: image, ImagePullPolicy: pull,
			Command: []string{"/usr/local/bin/netlock.sh"}, Env: env, SecurityContext: &fw,
		})
	}
	out = append(out, corev1.Container{
		Name: "agent-init", Image: image, ImagePullPolicy: pull,
		Command: []string{"/usr/local/bin/agent-init"}, Env: env,
		VolumeMounts: mounts, SecurityContext: secCtx,
	})
	return out
}

// deleteAndWait asks for the pod's deletion (idempotent) and blocks until the API server no
// longer knows it, bounded by ctx and twice the grace period plus a margin.
func (r *Runtime) deleteAndWait(ctx context.Context, name string) error {
	pods := r.Client.CoreV1().Pods(r.Cfg.Namespace)
	err := pods.Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	grace := r.Cfg.TerminationSeconds
	if grace == 0 {
		grace = 30
	}
	wctx, cancel := context.WithTimeout(ctx, time.Duration(2*grace+30)*time.Second)
	defer cancel()
	for {
		_, err := pods.Get(wctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("pod %s still terminating after %ds", name, 2*grace+30)
		case <-time.After(time.Second):
		}
	}
}

// PodStatus reports readiness and IP. Multus publishes the default-network IP as pod.Status.PodIP.
func (r *Runtime) PodStatus(ctx context.Context, sb *model.Sandbox) (bool, string, error) {
	name := sb.PodName
	if name == "" {
		name = podName(sb)
	}
	pod, err := r.Client.CoreV1().Pods(r.Cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, "", orchestrator.ErrPodNotFound
	}
	if err != nil {
		return false, "", err
	}
	switch pod.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		return false, pod.Status.PodIP, fmt.Errorf("%w: pod %s is %s", orchestrator.ErrPodTerminated, name, pod.Status.Phase)
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

// DeletePod removes the pod and waits until it is gone, so a pod created right after under the
// same name (sleep → wake, rollout) does not collide with the terminating one. The identity is
// retired by the orchestrator regardless.
func (r *Runtime) DeletePod(ctx context.Context, sb *model.Sandbox) error {
	name := sb.PodName
	if name == "" {
		name = podName(sb)
	}
	return r.deleteAndWait(ctx, name)
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
