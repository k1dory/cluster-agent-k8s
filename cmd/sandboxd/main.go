// sandboxd is the agent-sandbox control plane: orchestrator, registrar, authz, gateway
// configuration and APIs in one binary.
//
//	sandboxd [serve] -config sandboxd.yaml     run the service (default)
//	sandboxd policy validate [dir]             check policy files, list hosts
//	sandboxd policy test [dir] -f tests.yaml   run allow/deny expectations (CI)
//	sandboxd policy render -config sandboxd.yaml   print the Caddyfile that would be pushed
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/config"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/httpapi"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/kube"
	"agent-sandbox/internal/mcpproxy"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/oidc"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
	"agent-sandbox/internal/usage"
)

// Version is set at build time (-ldflags "-X main.Version=v1.2.3"); otherwise the VCS revision.
var Version = ""

func buildVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "dev-" + s.Value[:12]
			}
		}
	}
	return "dev"
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "policy" {
		os.Exit(policyCmd(args[1:]))
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config/sandboxd.yaml", "path to sandboxd.yaml")
	_ = fs.Parse(args)
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	if err := serve(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func gatewayConfig(cfg *config.Config) gateway.Config {
	g := cfg.Gateway
	return gateway.Config{
		IP: g.IP, CaddyAdmin: g.CaddyAdmin, CaddyfileOut: g.CaddyfileOut, SandboxdAddr: g.SandboxdAddr, IngressAddr: g.IngressAddr,
		APIHost: g.APIHost, RegistrarHost: g.RegistrarHost, RegistrarPort: g.RegistrarPort,
		PreviewDomain: cfg.Preview.Domain, PreviewTLS: g.PreviewTLS, AccessLog: g.AccessLog, StrictSNI: *g.StrictSNI,
	}
}

func serve(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "" {
		log.Warn("no database_url: using in-memory store, state is lost on restart")
		st = store.NewMemory()
	} else {
		pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		st = pg
	}
	defer st.Close()

	pols, err := policy.Load(cfg.PoliciesDir)
	if err != nil {
		return fmt.Errorf("policies: %w", err)
	}
	pols.Strict = cfg.PoliciesStrict
	log.Info("policies loaded", "slugs", pols.Slugs(), "hosts", len(pols.Hosts()), "strict", pols.Strict)
	go pols.Watch(ctx.Done(), 5*time.Second, func(err error) { log.Error("policy reload rejected, keeping previous policies", "err", err) })

	var agentCA *ca.CA
	if cfg.CA.Source == "db" {
		if agentCA, err = ca.LoadOrCreateShared(ctx, st); err != nil {
			return fmt.Errorf("ca (db): %w", err)
		}
		log.Info("agent CA loaded from the database (shared by replicas)")
	} else if agentCA, err = ca.LoadOrCreate(cfg.CA.Dir); err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	reg := &registrar.Registrar{CA: agentCA, Store: st, TTL: cfg.CA.CertTTL, Log: log}

	// Gateway: push Caddy config, learn Caddy's root, serve DNS.
	gwCfg := gatewayConfig(cfg)
	if cfg.CA.Source == "db" && cfg.Gateway.RootDir != "" {
		// One gateway root for every replica: Caddy signs its site certificates under it, so an
		// agent bootstrapped through one replica trusts the others.
		root, err := ca.LoadOrCreateSharedNamed(ctx, st, "gateway-ca", "agent-sandbox gateway root")
		if err != nil {
			return fmt.Errorf("gateway root (db): %w", err)
		}
		if gwCfg.RootCert, gwCfg.RootKey, err = root.WriteTo(cfg.Gateway.RootDir, "gateway-root"); err != nil {
			return fmt.Errorf("gateway root: %w", err)
		}
		log.Info("gateway root shared through the database", "dir", cfg.Gateway.RootDir)
	}
	if cfg.Gateway.CaddyAdmin != "" || cfg.Gateway.CaddyfileOut != "" {
		syncer := &gateway.Syncer{Cfg: gwCfg, Policies: pols, AgentCA: agentCA.PEM(), Log: log.With("log", "gateway")}
		go syncer.Run(ctx, cfg.Gateway.SyncEvery)
	}
	gatewayRoot := make(chan []byte, 1) // delivered once the root is known; published to pods below
	switch {
	case cfg.CA.GatewayCAFile != "":
		if reg.GatewayCA, err = os.ReadFile(cfg.CA.GatewayCAFile); err != nil {
			return fmt.Errorf("gateway ca: %w", err)
		}
		gatewayRoot <- reg.GatewayCA
	case cfg.Gateway.CaddyAdmin != "":
		go func() {
			for attempt := 1; ctx.Err() == nil; attempt++ {
				root, err := gateway.FetchRoot(ctx, cfg.Gateway.CaddyAdmin)
				if err == nil {
					reg.SetGatewayCA(root)
					log.Info("gateway root certificate fetched from caddy")
					gatewayRoot <- root
					return
				}
				log.Warn("gateway root not available yet", "attempt", attempt, "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(min(attempt, 12)) * 5 * time.Second):
				}
			}
		}()
	default:
		log.Warn("no gateway.caddy_admin and no ca.gateway_ca_file: pods will not get a gateway root to trust")
	}
	if cfg.Gateway.DNSListen != "" {
		ip := net.ParseIP(cfg.Gateway.IP)
		if ip == nil {
			return fmt.Errorf("gateway.ip %q is not an IP address", cfg.Gateway.IP)
		}
		d := &gateway.DNS{IP: ip, Policies: pols, Extra: gwCfg.InternalHosts(), Log: log.With("log", "dns")}
		go func() {
			if err := d.ListenAndServe(ctx, cfg.Gateway.DNSListen); err != nil {
				log.Error("dns", "err", err)
			}
		}()
		log.Info("dns listening", "addr", cfg.Gateway.DNSListen)
	}

	var rt orchestrator.Runtime
	// publishCA hands the gateway root to the pods (a ConfigMap in the agent namespace) so the
	// init container can trust the registrar before it holds any certificate.
	publishCA := func(context.Context, []byte) error { return nil }
	switch cfg.Runtime {
	case "kube":
		client, err := kube.NewClient(cfg.Kube.Kubeconfig)
		if err != nil {
			return fmt.Errorf("kubernetes: %w", err)
		}
		k := cfg.Kube
		rt = &kube.Runtime{Client: client, Cfg: kube.PodConfig{
			Namespace: k.Namespace, Image: k.Image, ImagePullPolicy: k.ImagePullPolicy, ServiceAccount: k.ServiceAccount,
			NetworkAttachment: k.NetworkAttachment, GatewayIP: k.GatewayIP, RegistrarURL: k.RegistrarURL, APIURL: k.APIURL,
			TokenAudience: k.TokenAudience, RuntimeClassName: k.RuntimeClassName, StorageClass: k.StorageClass,
			VolumeSize: k.VolumeSize, CPURequest: k.CPURequest, CPULimit: k.CPULimit, MemoryRequest: k.MemoryRequest,
			MemoryLimit: k.MemoryLimit, HarnessCommand: k.HarnessCommand, HarnessResumeCommand: k.HarnessResumeCommand,
			ResumePrompt: k.ResumePrompt, Env: k.Env, PriorityClassName: k.PriorityClassName,
			TerminationSeconds: k.TerminationSeconds, PodFirewall: *k.PodFirewall, GatewayCAConfigMap: *k.GatewayCAConfigMap,
		}}
		reg.Resolver = &kube.Resolver{Client: client, Namespace: k.Namespace, Audience: k.TokenAudience}
		publishCA = rt.(*kube.Runtime).PublishGatewayCA
	case "fake":
		log.Warn("runtime fake: no pods are created")
		rt = orchestrator.NewFakeRuntime()
		tokens := registrar.StaticResolver{}
		if cfg.BootstrapTokensFile != "" {
			raw, err := os.ReadFile(cfg.BootstrapTokensFile)
			if err != nil {
				return err
			}
			if err := yaml.Unmarshal(raw, &tokens); err != nil {
				return fmt.Errorf("bootstrap tokens: %w", err)
			}
		}
		reg.Resolver = tokens
	default:
		return fmt.Errorf("unknown runtime %q", cfg.Runtime)
	}

	go func() {
		select {
		case <-ctx.Done():
		case root := <-gatewayRoot:
			for attempt := 1; ctx.Err() == nil; attempt++ {
				err := publishCA(ctx, root)
				if err == nil {
					log.Info("gateway root published to the agent namespace")
					return
				}
				log.Warn("publish gateway root", "attempt", attempt, "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(min(attempt, 12)) * 5 * time.Second):
				}
			}
		}
	}()

	hub := events.New()
	// Events appended by any replica (this one included) reach the SSE clients through the store,
	// so the orchestrator does not publish locally as well.
	listener, hasListener := st.(store.EventListener)
	if hasListener {
		go listener.ListenEvents(ctx, func(e *model.Event) { hub.Publish(*e) })
	}
	// The environment version: everything that shapes a pod besides the task. A change here
	// shows as drift between a sandbox's env_version and GET /v1/version.
	envVersion := func(sb *model.Sandbox) string {
		h := sha256.New()
		fmt.Fprintf(h, "policy=%s\nimage=%s\nharness=%s\nresume=%s\n", pols.ContentHash(sb.Slug), sb.AgentVersion, cfg.Kube.HarnessCommand, cfg.Kube.HarnessResumeCommand)
		if sb.Launch != nil {
			b, _ := json.Marshal(sb.Launch)
			fmt.Fprintf(h, "launch=%s\nagent=%s@%d\nenvironment=%s@%d\n", b, sb.AgentRef, sb.AgentRevision, sb.EnvironmentRef, sb.EnvironmentRevision)
		}
		keys := make([]string, 0, len(cfg.Kube.Env))
		for k := range cfg.Kube.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(h, "env %s=%s\n", k, cfg.Kube.Env[k])
		}
		fmt.Fprintf(h, "runtime=%s\nresources=%s/%s/%s/%s\n", cfg.Kube.RuntimeClassName, cfg.Kube.CPURequest, cfg.Kube.CPULimit, cfg.Kube.MemoryRequest, cfg.Kube.MemoryLimit)
		return hex.EncodeToString(h.Sum(nil))[:12]
	}
	orch := orchestrator.New(st, rt, reg, hub, orchestrator.Config{
		DefaultIdleTimeout: cfg.Sandbox.DefaultIdleTimeout, PreviewDomain: cfg.Preview.Domain,
		ReadyTimeout: cfg.Sandbox.ReadyTimeout, IdleCheckEvery: cfg.Sandbox.IdleCheckEvery,
		DefaultQuota: cfg.Quotas.Default, Quotas: cfg.Quotas.Tenants,
		DefaultAgentVersion: cfg.Agent.Default, Versions: cfg.Agent.Versions, EnvVersion: envVersion,
	}, log)
	// Ownership: the policy repository's lists plus the admin's PolicyBindings; quotas: the
	// server defaults overridden by TenantSettings, and per-slug limits from the bindings.
	bind := bindings.New(st, pols)
	tset := tenants.New(st, func(t string) tenants.Quota {
		q := orch.Cfg.QuotaFor(t)
		return tenants.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
	})
	for name, r := range map[string]interface{ Refresh(context.Context) error }{"bindings": bind, "tenant settings": tset} {
		if err := r.Refresh(ctx); err != nil {
			return fmt.Errorf("load %s: %w", name, err)
		}
	}
	go bind.Watch(ctx, log)
	go tset.Watch(ctx, log)
	guard := &bindings.Guard{Set: pols, Bindings: bind}
	orch.Policies = guard
	orch.Quotas = limits{tenants: tset, bindings: bind}
	orch.ListenerPublishes = hasListener
	go orch.Run(ctx) // reconciler on the replica holding the lease

	var secretProvider secrets.Provider = secrets.Static{}
	switch cfg.Secrets.Provider {
	case "file":
		secretProvider = secrets.FileProvider{Dir: cfg.SecretsDir}
	case "vault":
		v, err := secrets.NewVault(cfg.Secrets.Vault)
		if err != nil {
			return fmt.Errorf("secrets: %w", err)
		}
		secretProvider = secrets.NewCached(v, cfg.Secrets.CacheTTL)
	case "infisical":
		i, err := secrets.NewInfisical(cfg.Secrets.Infisical)
		if err != nil {
			return fmt.Errorf("secrets: %w", err)
		}
		secretProvider = secrets.NewCached(i, cfg.Secrets.CacheTTL)
	default:
		log.Warn("no secrets provider configured: secret: references in policies cannot be resolved")
	}
	log.Info("secrets provider", "provider", cfg.Secrets.Provider)
	az := &authz.Handler{Policies: guard, Secrets: secretProvider, Checker: reg, Toucher: orch, Recorder: orch,
		Trace: cfg.Accounting.EgressTrace, Quiet: map[string]bool{cfg.Gateway.APIHost: true}, Audit: log.With("log", "egress")}

	var ing *ingress.Handler
	if cfg.Listen.Ingress != "" {
		ing = &ingress.Handler{Store: st, Waker: orch, AuthURL: cfg.Preview.AuthURL, TicketKey: []byte(cfg.Preview.TicketKey),
			CookieTTL: cfg.Preview.CookieTTL, HitsAsActivity: cfg.Preview.HitsAsActivity, Log: log}
	}

	tokenTenants := map[string]string{}
	for _, t := range cfg.APITokens {
		tokenTenants[t.Token] = t.Tenant
	}
	conns := &connections.Service{Store: st, Secrets: secretProvider}
	cat := &catalog.Service{Store: st, Images: orch.Cfg, Policies: guard, Connections: conns, Tenants: tset}
	platform := &httpapi.Platform{Orch: orch, Hub: hub, Policies: pols, Ingress: ing, Catalog: cat, Connections: conns, Bindings: bind,
		TenantSettings: tset, Token: cfg.APIToken, Tenants: tokenTenants,
		Pricing: usage.Pricing{PodHourUSD: cfg.Accounting.PodHourUSD}, Build: buildVersion(), Log: log.With("log", "api")}
	if cfg.OIDC != nil {
		v, err := oidc.New(*cfg.OIDC)
		if err != nil {
			return fmt.Errorf("oidc: %w", err)
		}
		platform.Verifier, platform.TTLFromToken = v, cfg.OIDC.TTLFromToken
		log.Info("oidc enabled", "issuer", cfg.OIDC.Issuer, "ttl_from_token", cfg.OIDC.TTLFromToken)
	}
	if cfg.APIToken == "" && len(tokenTenants) == 0 && cfg.OIDC == nil {
		return errors.New("no api_token, api_tokens or oidc configured: nobody could call the API")
	}
	gw := &httpapi.Gateway{Orch: orch, Registrar: reg, Authz: az, Log: log.With("log", "gateway-api"),
		MCP: &mcpproxy.Handler{Authz: az, Hosts: pols, Log: log.With("log", "mcp")}}

	servers := []*http.Server{
		{Addr: cfg.Listen.API, Handler: platform.Routes(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: cfg.Listen.Gateway, Handler: gw.Routes(), ReadHeaderTimeout: 10 * time.Second},
	}
	if ing != nil {
		servers = append(servers, &http.Server{Addr: cfg.Listen.Ingress, Handler: ing, ReadHeaderTimeout: 10 * time.Second})
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			log.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s)
	}
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		return err
	}
	for _, s := range servers {
		httpapi.ShutdownServer(context.Background(), s)
	}
	return nil
}

// policyCmd implements `sandboxd policy ...` for Policy-as-Code pipelines.
func policyCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sandboxd policy validate [dir] | test [dir] -f tests.yaml | render -config sandboxd.yaml")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "validate":
		dir := "policies"
		if len(rest) > 0 {
			dir = rest[0]
		}
		set, err := policy.Load(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		fmt.Printf("OK: %d policies (%v)\n", len(set.Slugs()), set.Slugs())
		for _, h := range set.Hosts() {
			fmt.Printf("  host %-32s -> %-40s strip %v\n", h.Name, h.Upstream, h.Injected)
		}
		return 0
	case "test":
		fs := flag.NewFlagSet("policy test", flag.ExitOnError)
		file := fs.String("f", "policies/tests.yaml", "expectations file")
		dir := "policies"
		if len(rest) > 0 && rest[0][0] != '-' {
			dir, rest = rest[0], rest[1:]
		}
		_ = fs.Parse(rest)
		set, err := policy.Load(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		ex, err := policy.LoadExpectations(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		res, err := set.RunTests(ex)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		failed := 0
		for _, r := range res {
			mark := "PASS"
			if !r.Pass() {
				mark = "FAIL"
				failed++
			}
			want := "deny"
			if r.Want {
				want = "allow"
			}
			fmt.Printf("%s  %-14s %-5s %-60s %s\n", mark, r.Slug, want, r.Line, r.Reason)
		}
		fmt.Printf("%d checks, %d failed\n", len(res), failed)
		if failed > 0 {
			return 1
		}
		return 0
	case "render":
		fs := flag.NewFlagSet("policy render", flag.ExitOnError)
		cfgPath := fs.String("config", "config/sandboxd.yaml", "path to sandboxd.yaml")
		_ = fs.Parse(rest)
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		set, err := policy.Load(cfg.PoliciesDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		agentCA, err := ca.LoadOrCreate(cfg.CA.Dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out, err := gateway.Render(gatewayConfig(cfg), set.Hosts(), agentCA.PEM())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Print(out)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown policy subcommand", sub)
		return 2
	}
}

// limits composes the orchestrator's quotas from tenant settings and policy bindings.
type limits struct {
	tenants  *tenants.Service
	bindings *bindings.Service
}

func (l limits) QuotaFor(tenant string) orchestrator.Quota {
	q := l.tenants.QuotaFor(tenant)
	return orchestrator.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
}

func (l limits) SlugQuota(slug, tenant string) orchestrator.Quota {
	if b, ok := l.bindings.Active(slug, tenant); ok {
		return orchestrator.Quota{MaxSandboxes: b.MaxSandboxes, MaxAwake: b.MaxAwake}
	}
	return orchestrator.Quota{}
}
