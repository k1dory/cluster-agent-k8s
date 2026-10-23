// Package config loads sandboxd.yaml with ${ENV} expansion.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole sandboxd configuration. Secrets (API token, DB URL) are referenced
// through environment variables so the file can live in git.
type Config struct {
	Listen struct {
		API     string `yaml:"api"`     // frontend-facing, default :8080
		Gateway string `yaml:"gateway"` // Caddy-facing, default 127.0.0.1:8081
		Ingress string `yaml:"ingress"` // preview proxy, default :8082 ("" disables)
	} `yaml:"listen"`
	APIToken    string `yaml:"api_token"`
	DatabaseURL string `yaml:"database_url"` // empty → in-memory store
	PoliciesDir string `yaml:"policies_dir"`
	SecretsDir  string `yaml:"secrets_dir"`
	CA          struct {
		Dir           string        `yaml:"dir"` // ca.crt + ca.key, generated if missing
		CertTTL       time.Duration `yaml:"cert_ttl"`
		GatewayCAFile string        `yaml:"gateway_ca_file"` // Caddy root handed to pods
	} `yaml:"ca"`
	Runtime string `yaml:"runtime"` // kube | fake
	Kube    struct {
		Kubeconfig         string            `yaml:"kubeconfig"`
		Namespace          string            `yaml:"namespace"`
		Image              string            `yaml:"image"`
		ImagePullPolicy    string            `yaml:"image_pull_policy"`
		ServiceAccount     string            `yaml:"service_account"`
		NetworkAttachment  string            `yaml:"network_attachment"`
		GatewayIP          string            `yaml:"gateway_ip"`
		RegistrarURL       string            `yaml:"registrar_url"`
		APIURL             string            `yaml:"api_url"`
		TokenAudience      string            `yaml:"token_audience"`
		RuntimeClassName   string            `yaml:"runtime_class"`
		StorageClass       string            `yaml:"storage_class"`
		VolumeSize         string            `yaml:"volume_size"`
		CPURequest         string            `yaml:"cpu_request"`
		CPULimit           string            `yaml:"cpu_limit"`
		MemoryRequest      string            `yaml:"memory_request"`
		MemoryLimit        string            `yaml:"memory_limit"`
		HarnessCommand     string            `yaml:"harness_command"`
		Env                map[string]string `yaml:"env"`
		PriorityClassName  string            `yaml:"priority_class"`
		TerminationSeconds int64             `yaml:"termination_seconds"`
	} `yaml:"kube"`
	BootstrapTokensFile string `yaml:"bootstrap_tokens_file"` // fake runtime: static token → pod table
	Sandbox             struct {
		DefaultIdleTimeout time.Duration `yaml:"default_idle_timeout"`
		ReadyTimeout       time.Duration `yaml:"ready_timeout"`
		IdleCheckEvery     time.Duration `yaml:"idle_check_every"`
	} `yaml:"sandbox"`
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
	if c.Runtime == "" {
		c.Runtime = "kube"
	}
	if c.Kube.Namespace == "" {
		c.Kube.Namespace = "agent-sandbox"
	}
	if c.Kube.TokenAudience == "" {
		c.Kube.TokenAudience = "agent-sandbox"
	}
	if c.Runtime == "kube" {
		for k, v := range map[string]string{"kube.image": c.Kube.Image, "kube.network_attachment": c.Kube.NetworkAttachment,
			"kube.gateway_ip": c.Kube.GatewayIP, "kube.registrar_url": c.Kube.RegistrarURL, "kube.api_url": c.Kube.APIURL} {
			if v == "" {
				return nil, fmt.Errorf("%s: %s is required for runtime kube", path, k)
			}
		}
	}
	if c.Preview.Domain == "" {
		c.Preview.Domain = "preview.localhost"
	}
	return &c, nil
}
