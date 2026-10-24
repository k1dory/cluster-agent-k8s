// Package config loads sandboxd.yaml with ${ENV} expansion.
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"agent-sandbox/internal/oidc"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/secrets"
)

// Config is the whole sandboxd configuration. Secrets (API token, DB URL) are referenced
// through environment variables so the file can live in git.
type Config struct {
	Listen struct {
		API     string `yaml:"api"`     // client-facing, default :8080
		Gateway string `yaml:"gateway"` // Caddy-facing, default 127.0.0.1:8081
		Ingress string `yaml:"ingress"` // preview proxy, default :8082 ("" disables)
	} `yaml:"listen"`
	APIToken string `yaml:"api_token"` // admin token: every tenant
	// Tenant-scoped tokens: a client holding one sees and creates only that tenant's sandboxes.
	APITokens []struct {
		Token  string `yaml:"token"`
		Tenant string `yaml:"tenant"`
	} `yaml:"api_tokens"`
	// Quotas per tenant; `default` applies to tenants not listed. Zero = unlimited.
	Quotas struct {
		Default orchestrator.Quota            `yaml:"default"`
		Tenants map[string]orchestrator.Quota `yaml:"tenants"`
	} `yaml:"quotas"`
	// OIDC: bearer JWTs from this issuer are accepted next to the static tokens.
	OIDC        *oidc.Config `yaml:"oidc"`
	DatabaseURL string       `yaml:"database_url"` // empty → in-memory store
	PoliciesDir string       `yaml:"policies_dir"`
	// PoliciesStrict: a policy without a tenants list is admin-only and a slug without a policy
	// file is refused for tenants (no silent fallback to default).
	PoliciesStrict bool   `yaml:"policies_strict"`
	SecretsDir     string `yaml:"secrets_dir"` // file provider (tenants/<t>/<name>, shared/<name>)
	// Secrets: where `secret:NAME` references in policies are resolved. provider file (default
	// when secrets_dir is set), vault (Vault or OpenBao KV v2) or infisical.
	Secrets struct {
		Provider  string                  `yaml:"provider"`
		CacheTTL  time.Duration           `yaml:"cache_ttl"` // default 60s
		Vault     secrets.VaultConfig     `yaml:"vault"`
		Infisical secrets.InfisicalConfig `yaml:"infisical"`
	} `yaml:"secrets"`
	CA struct {
		Dir           string        `yaml:"dir"`    // ca.crt + ca.key, generated if missing
		Source        string        `yaml:"source"` // file (default) | db: key shared by replicas through Postgres
		CertTTL       time.Duration `yaml:"cert_ttl"`
		GatewayCAFile string        `yaml:"gateway_ca_file"` // optional override; normally fetched from Caddy's admin API
	} `yaml:"ca"`
	// Agent versions: what `agent_version` in the API may name. default is the image used when
	// a request names none; versions maps names (stable, canary, 1.5.0) to image references.
	// Tenants are confined to these names, the admin may also pass any image reference.
	Agent struct {
		Default  string            `yaml:"default"`
		Versions map[string]string `yaml:"versions"`
	} `yaml:"agent"`
	// Gateway: sandboxd drives Caddy and serves DNS; nothing on the gateway is configured by hand.
	Gateway struct {
		IP            string        `yaml:"ip"`             // gateway address on the sandbox VLAN
		CaddyAdmin    string        `yaml:"caddy_admin"`    // http://127.0.0.1:2019; "" = render only
		CaddyfileOut  string        `yaml:"caddyfile_out"`  // rendered copy for inspection
		DNSListen     string        `yaml:"dns_listen"`     // "10.77.77.1:53"; "" disables the built-in DNS
		APIHost       string        `yaml:"api_host"`       // default api.sandbox.internal
		RegistrarHost string        `yaml:"registrar_host"` // default registrar.sandbox.internal
		RegistrarPort int           `yaml:"registrar_port"` // default 8443
		SandboxdAddr  string        `yaml:"sandboxd_addr"`  // how Caddy reaches listen.gateway (default derived)
		IngressAddr   string        `yaml:"ingress_addr"`   // how Caddy reaches listen.ingress (default derived)
		PreviewTLS    string        `yaml:"preview_tls"`    // e.g. "dns cloudflare {env.CF_API_TOKEN}"; "" = on_demand
		AccessLog     string        `yaml:"access_log"`     // "stdout" or a file path
		StrictSNI     *bool         `yaml:"strict_sni"`     // default true
		SyncEvery     time.Duration `yaml:"sync_every"`     // policy → Caddy re-sync interval, default 5s
	} `yaml:"gateway"`
	Runtime string `yaml:"runtime"` // kube | fake
	Kube    struct {
		Kubeconfig        string `yaml:"kubeconfig"`
		Namespace         string `yaml:"namespace"`
		Image             string `yaml:"image"`
		ImagePullPolicy   string `yaml:"image_pull_policy"`
		ServiceAccount    string `yaml:"service_account"`
		NetworkAttachment string `yaml:"network_attachment"`
		GatewayIP         string `yaml:"gateway_ip"`
		RegistrarURL      string `yaml:"registrar_url"`
		APIURL            string `yaml:"api_url"`
		TokenAudience     string `yaml:"token_audience"`
		RuntimeClassName  string `yaml:"runtime_class"`
		StorageClass      string `yaml:"storage_class"`
		VolumeSize        string `yaml:"volume_size"`
		CPURequest        string `yaml:"cpu_request"`
		CPULimit          string `yaml:"cpu_limit"`
		MemoryRequest     string `yaml:"memory_request"`
		MemoryLimit       string `yaml:"memory_limit"`
		HarnessCommand    string `yaml:"harness_command"`
		// HarnessResumeCommand continues a run interrupted by a forced rollout: $SANDBOX_SESSION
		// is the harness session id captured from its output, $SANDBOX_RESUME_PROMPT the text to
		// continue with. Default: Claude Code's --resume. Codex: 'codex exec resume "$SANDBOX_SESSION" "$SANDBOX_RESUME_PROMPT" --json'.
		HarnessResumeCommand string            `yaml:"harness_resume_command"`
		ResumePrompt         string            `yaml:"resume_prompt"`
		Env                  map[string]string `yaml:"env"`
		PriorityClassName    string            `yaml:"priority_class"`
		TerminationSeconds   int64             `yaml:"termination_seconds"`
	} `yaml:"kube"`
	BootstrapTokensFile string `yaml:"bootstrap_tokens_file"` // fake runtime: static token → pod table
	Sandbox             struct {
		DefaultIdleTimeout time.Duration `yaml:"default_idle_timeout"`
		ReadyTimeout       time.Duration `yaml:"ready_timeout"`
		IdleCheckEvery     time.Duration `yaml:"idle_check_every"`
	} `yaml:"sandbox"`
	// Accounting: what GET /v1/usage prices and how much of the gateway traffic lands in the trace.
	Accounting struct {
		PodHourUSD  float64 `yaml:"pod_hour_usd"` // price of one sandbox pod-hour; 0 = report time only
		EgressTrace string  `yaml:"egress_trace"` // all (default) | denied | off
	} `yaml:"accounting"`
	Preview struct {
		Domain         string        `yaml:"domain"`
		AuthURL        string        `yaml:"auth_url"`
		TicketKey      string        `yaml:"ticket_key"`
		CookieTTL      time.Duration `yaml:"cookie_ttl"`
		HitsAsActivity bool          `yaml:"hits_as_activity"`
	} `yaml:"preview"`
}

// Load reads the file, expands ${VARS} and applies defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(raw))), &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen.API == "" {
		c.Listen.API = ":8080"
	}
	if c.Listen.Gateway == "" {
		c.Listen.Gateway = "127.0.0.1:8081"
	}
	if c.PoliciesDir == "" {
		c.PoliciesDir = "policies"
	}
	if c.CA.Dir == "" {
		c.CA.Dir = "var/ca"
	}
	if c.CA.CertTTL == 0 {
		c.CA.CertTTL = 7 * 24 * time.Hour
	}
	switch c.CA.Source {
	case "":
		c.CA.Source = "file"
	case "file":
	case "db":
		if c.DatabaseURL == "" {
			return nil, fmt.Errorf("%s: ca.source db needs database_url", path)
		}
	default:
		return nil, fmt.Errorf("%s: ca.source must be file or db", path)
	}
	switch c.Secrets.Provider {
	case "":
		if c.SecretsDir != "" {
			c.Secrets.Provider = "file"
		}
	case "file":
		if c.SecretsDir == "" {
			return nil, fmt.Errorf("%s: secrets.provider file needs secrets_dir", path)
		}
	case "vault", "infisical":
	default:
		return nil, fmt.Errorf("%s: secrets.provider must be file, vault or infisical", path)
	}
	if c.Secrets.CacheTTL == 0 {
		c.Secrets.CacheTTL = time.Minute
	}
	if c.OIDC != nil && c.OIDC.Issuer == "" {
		return nil, fmt.Errorf("%s: oidc.issuer is required when oidc is set", path)
	}
	if c.Agent.Default == "" {
		c.Agent.Default = c.Kube.Image
	}
	if c.Kube.Image == "" {
		c.Kube.Image = c.Agent.Default
	}
	if c.Kube.HarnessResumeCommand == "" {
		c.Kube.HarnessResumeCommand = `claude -p "$SANDBOX_RESUME_PROMPT" --resume "$SANDBOX_SESSION" --output-format stream-json --verbose`
	}
	if c.Runtime == "" {
		c.Runtime = "kube"
	}
	if c.Kube.Namespace == "" {
		c.Kube.Namespace = "agent-sandbox"
	}
	if c.Kube.TokenAudience == "" {
		c.Kube.TokenAudience = "agent-sandbox"
	}
	if c.Preview.Domain == "" {
		c.Preview.Domain = "preview.localhost"
	}
	for i, t := range c.APITokens {
		if t.Token == "" || t.Tenant == "" {
			return nil, fmt.Errorf("%s: api_tokens[%d]: token and tenant are required", path, i)
		}
		if t.Token == c.APIToken {
			return nil, fmt.Errorf("%s: api_tokens[%d]: same value as api_token", path, i)
		}
	}
	switch c.Accounting.EgressTrace {
	case "":
		c.Accounting.EgressTrace = "all"
	case "all", "denied", "off":
	default:
		return nil, fmt.Errorf("%s: accounting.egress_trace must be all, denied or off", path)
	}
	g := &c.Gateway
	if g.APIHost == "" {
		g.APIHost = "api.sandbox.internal"
	}
	if g.RegistrarHost == "" {
		g.RegistrarHost = "registrar.sandbox.internal"
	}
	if g.RegistrarPort == 0 {
		g.RegistrarPort = 8443
	}
	if g.SandboxdAddr == "" {
		g.SandboxdAddr = loopbackFor(c.Listen.Gateway)
	}
	if g.IngressAddr == "" && c.Listen.Ingress != "" {
		g.IngressAddr = loopbackFor(c.Listen.Ingress)
	}
	if g.AccessLog == "" {
		g.AccessLog = "stdout"
	}
	if g.StrictSNI == nil {
		t := true
		g.StrictSNI = &t
	}
	if g.SyncEvery == 0 {
		g.SyncEvery = 5 * time.Second
	}
	if c.Kube.GatewayIP == "" {
		c.Kube.GatewayIP = g.IP
	}
	if c.Kube.RegistrarURL == "" {
		c.Kube.RegistrarURL = fmt.Sprintf("https://%s:%d", g.RegistrarHost, g.RegistrarPort)
	}
	if c.Kube.APIURL == "" {
		c.Kube.APIURL = "https://" + g.APIHost
	}
	if c.Runtime == "kube" {
		for k, v := range map[string]string{"kube.image": c.Kube.Image, "kube.network_attachment": c.Kube.NetworkAttachment, "gateway.ip": g.IP} {
			if v == "" {
				return nil, fmt.Errorf("%s: %s is required for runtime kube", path, k)
			}
		}
	}
	return &c, nil
}

// loopbackFor turns a listen address like ":8081" or "0.0.0.0:8081" into a dial address Caddy can use.
func loopbackFor(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
