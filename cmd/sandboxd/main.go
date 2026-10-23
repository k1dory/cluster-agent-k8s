// sandboxd is the agent-sandbox control plane: orchestrator, registrar, authz and APIs in one binary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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
	"agent-sandbox/internal/httpapi"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/kube"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func main() {
	cfgPath := flag.String("config", "config/sandboxd.yaml", "path to sandboxd.yaml")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Store.
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

	// Policies with hot reload.
	pols, err := policy.Load(cfg.PoliciesDir)
	if err != nil {
		return fmt.Errorf("policies: %w", err)
	}
	log.Info("policies loaded", "slugs", pols.Slugs())
	go pols.Watch(ctx.Done(), 5*time.Second, func(err error) { log.Error("policy reload", "err", err) })

	// CA and Registrar.
	agentCA, err := ca.LoadOrCreate(cfg.CA.Dir)
	if err != nil {
		return fmt.Errorf("ca: %w", err)
	}
	var gatewayCA []byte
	if cfg.CA.GatewayCAFile != "" {
		if gatewayCA, err = os.ReadFile(cfg.CA.GatewayCAFile); err != nil {
			return fmt.Errorf("gateway ca: %w", err)
		}
	}
	reg := &registrar.Registrar{CA: agentCA, Store: st, TTL: cfg.CA.CertTTL, GatewayCA: gatewayCA, Log: log}

	// Runtime.
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
	az := &authz.Handler{Policies: pols, Secrets: secretProvider, Checker: reg, Toucher: orch, Audit: log.With("log", "egress")}

	var ing *ingress.Handler
	if cfg.Listen.Ingress != "" {
		ing = &ingress.Handler{Store: st, Waker: orch, AuthURL: cfg.Preview.AuthURL, TicketKey: []byte(cfg.Preview.TicketKey),
			CookieTTL: cfg.Preview.CookieTTL, HitsAsActivity: cfg.Preview.HitsAsActivity, Log: log}
	}

	platform := &httpapi.Platform{Orch: orch, Hub: hub, Policies: pols, Ingress: ing, Token: cfg.APIToken, Log: log.With("log", "api")}
	gateway := &httpapi.Gateway{Orch: orch, Registrar: reg, Authz: az, Log: log.With("log", "gateway")}

	servers := []*http.Server{
		{Addr: cfg.Listen.API, Handler: platform.Routes(), ReadHeaderTimeout: 10 * time.Second},
		{Addr: cfg.Listen.Gateway, Handler: gateway.Routes(), ReadHeaderTimeout: 10 * time.Second},
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
