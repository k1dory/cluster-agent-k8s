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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/config"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/httpapi"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/kube"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/usage"
)

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
	log.Info("policies loaded", "slugs", pols.Slugs(), "hosts", len(pols.Hosts()))
	go pols.Watch(ctx.Done(), 5*time.Second, func(err error) { log.Error("policy reload rejected, keeping previous policies", "err", err) })

	agentCA, err := ca.LoadOrCreate(cfg.CA.Dir)
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	reg := &registrar.Registrar{CA: agentCA, Store: st, TTL: cfg.CA.CertTTL, Log: log}

	// Gateway: push Caddy config, learn Caddy's root, serve DNS.
	gwCfg := gatewayConfig(cfg)
	if cfg.Gateway.CaddyAdmin != "" || cfg.Gateway.CaddyfileOut != "" {
		syncer := &gateway.Syncer{Cfg: gwCfg, Policies: pols, AgentCA: agentCA.PEM(), Log: log.With("log", "gateway")}
		go syncer.Run(ctx, cfg.Gateway.SyncEvery)
	}
	switch {
	case cfg.CA.GatewayCAFile != "":
		if reg.GatewayCA, err = os.ReadFile(cfg.CA.GatewayCAFile); err != nil {
			return fmt.Errorf("gateway ca: %w", err)
		}
	case cfg.Gateway.CaddyAdmin != "":
		go func() {
			for attempt := 1; ctx.Err() == nil; attempt++ {
				root, err := gateway.FetchRoot(ctx, cfg.Gateway.CaddyAdmin)
				if err == nil {
					reg.SetGatewayCA(root)
					log.Info("gateway root certificate fetched from caddy")
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
			MemoryLimit: k.MemoryLimit, HarnessCommand: k.HarnessCommand, Env: k.Env, PriorityClassName: k.PriorityClassName,
			TerminationSeconds: k.TerminationSeconds,
		}}
		reg.Resolver = &kube.Resolver{Client: client, Namespace: k.Namespace, Audience: k.TokenAudience}
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

	hub := events.New()
	orch := orchestrator.New(st, rt, reg, hub, orchestrator.Config{
		DefaultIdleTimeout: cfg.Sandbox.DefaultIdleTimeout, PreviewDomain: cfg.Preview.Domain,
		ReadyTimeout: cfg.Sandbox.ReadyTimeout, IdleCheckEvery: cfg.Sandbox.IdleCheckEvery,
	}, log)
	go orch.IdleLoop(ctx)

	var secretProvider secrets.Provider = secrets.Static{}
	if cfg.SecretsDir != "" {
		secretProvider = secrets.FileProvider{Dir: cfg.SecretsDir}
	}
	az := &authz.Handler{Policies: pols, Secrets: secretProvider, Checker: reg, Toucher: orch, Recorder: orch,
		Trace: cfg.Accounting.EgressTrace, Quiet: map[string]bool{cfg.Gateway.APIHost: true}, Audit: log.With("log", "egress")}

	var ing *ingress.Handler
	if cfg.Listen.Ingress != "" {
		ing = &ingress.Handler{Store: st, Waker: orch, AuthURL: cfg.Preview.AuthURL, TicketKey: []byte(cfg.Preview.TicketKey),
			CookieTTL: cfg.Preview.CookieTTL, HitsAsActivity: cfg.Preview.HitsAsActivity, Log: log}
	}

	platform := &httpapi.Platform{Orch: orch, Hub: hub, Policies: pols, Ingress: ing, Token: cfg.APIToken,
		Pricing: usage.Pricing{PodHourUSD: cfg.Accounting.PodHourUSD}, Log: log.With("log", "api")}
	gw := &httpapi.Gateway{Orch: orch, Registrar: reg, Authz: az, Log: log.With("log", "gateway-api")}

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
