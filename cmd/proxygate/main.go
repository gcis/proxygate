package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/api"
	"github.com/gcis/proxygate/internal/auth"
	"github.com/gcis/proxygate/internal/certmanager"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

var version = "dev"

// configProviderAdapter adapts *config.Manager (Get() *Config) to the
// certmanager.ConfigProvider interface (Get() Config).
type configProviderAdapter struct {
	mgr *config.Manager
}

func (a *configProviderAdapter) Get() config.Config {
	return *a.mgr.Get()
}

// acmeRequesterAdapter adapts *acme.Client to certmanager.CertRequester.
// It calls RequestCertificate first (to initiate the DNS-01 challenge), then
// CompleteChallengeAndFetchCert (which waits for propagation and retrieves the cert).
// Between the two it publishes the TXT record via the DNS provider — without
// that step Let's Encrypt never sees the challenge and renewal always fails.
type acmeRequesterAdapter struct {
	client *acme.Client
	dns    acme.DNSProvider
	// propagationWait is how long to wait after creating the TXT record.
	propagationWait time.Duration
}

func (a *acmeRequesterAdapter) RenewForDomain(ctx context.Context, domain string) (certPath, keyPath string, err error) {
	if err = a.client.Register(ctx); err != nil {
		return "", "", fmt.Errorf("acme register: %w", err)
	}
	status, err := a.client.RequestCertificate(ctx, domain)
	if err != nil {
		return "", "", fmt.Errorf("acme request: %w", err)
	}
	if a.dns == nil {
		return "", "", fmt.Errorf("no DNS provider configured for DNS-01 challenge")
	}
	if err = a.dns.CreateTXTRecord(ctx, domain, status.RecordName, status.RecordVal); err != nil {
		return "", "", fmt.Errorf("creating TXT record: %w", err)
	}
	select {
	case <-time.After(a.propagationWait):
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
	return a.client.CompleteChallengeAndFetchCert(ctx, domain)
}

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	// SIGINT/SIGTERM cancel the context, which triggers a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run starts ProxyGate and blocks until ctx is cancelled. It returns the
// process exit code: 0 on clean shutdown, 1 on a startup failure, 2 on bad
// flags. Maintenance subcommands (passwd, token) run and return instead.
func run(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if handled, code := runAdminCommand(args, stdin, stdout, stderr); handled {
		return code
	}

	fs := flag.NewFlagSet("proxygate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath      = fs.String("config", "./data/proxygate.json", "Path to config file")
		showVersion     = fs.Bool("version", false, "Print version and exit")
		allowedNetworks multiFlag
	)
	fs.Var(&allowedNetworks, "allow-network", "Allow admin UI access from this CIDR (can be repeated)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: proxygate [flags]")
		fmt.Fprintln(fs.Output(), "       proxygate passwd [--config path] [--generate] [--policy strong|basic]")
		fmt.Fprintln(fs.Output(), "       proxygate token create|list|revoke [name] [--config path]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, "proxygate", version)
		return 0
	}

	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("starting ProxyGate", "version", version)

	// Load or create config
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		return 1
	}

	// Apply CLI-provided network allowlist on top of config file
	if len(allowedNetworks) > 0 {
		if err := cfgMgr.Update(func(cfg *config.Config) {
			// Merge: keep existing + add CLI networks (dedup)
			existing := make(map[string]bool)
			for _, n := range cfg.Server.AllowedNetworks {
				existing[n] = true
			}
			for _, n := range allowedNetworks {
				if !existing[n] {
					cfg.Server.AllowedNetworks = append(cfg.Server.AllowedNetworks, n)
					existing[n] = true
				}
			}
		}); err != nil {
			logger.Error("failed to update allowed networks", "error", err)
			return 1
		}
		logger.Info("applied CLI network allowlist", "networks", []string(allowedNetworks))
	}

	cfg := cfgMgr.Get()

	if st := cfgMgr.SecretsStatus(); st.Error != "" {
		logger.Warn("stored GoDaddy credentials and ACME email could not be decrypted; "+
			"the proxy keeps running, re-enter them in the admin UI or restore the key and restart",
			"error", st.Error)
	}

	// The admin UI stays locked until a password exists. The one-time setup
	// code is written to a file readable only by this user; never logged.
	authStore := auth.NewStore(filepath.Dir(*configPath))
	if required, err := authStore.SetupRequired(); err != nil {
		logger.Error("reading admin credentials", "error", err)
		return 1
	} else if required {
		codePath, err := authStore.EnsureSetupCode()
		if err != nil {
			logger.Error("creating setup code", "error", err)
			return 1
		}
		logger.Warn("admin UI is locked until first setup: open it and enter the one-time code from the setup file "+
			"(or run 'proxygate passwd')", "setup_code_file", codePath)
	}

	// Init ACME client
	acmeClient, err := acme.NewClient(
		cfg.ACME.Email,
		cfg.ACME.CertDir,
		cfg.ACME.Directory,
		logger,
	)
	if err != nil {
		logger.Error("failed to init ACME client", "error", err)
		return 1
	}

	// Init GoDaddy client
	godaddyClient := godaddy.NewClient(
		cfg.GoDaddy.APIKey,
		cfg.GoDaddy.APISecret,
		cfg.GoDaddy.BaseURL,
		logger,
	)

	// Init proxy engine
	engine := proxy.NewEngine(cfgMgr, logger)
	if err := engine.Start(cfg); err != nil {
		logger.Error("failed to start proxy engine", "error", err)
		return 1
	}

	// Init certificate manager (automatic renewal + hot reload)
	certMgr := certmanager.NewManager(
		engine,
		&acmeRequesterAdapter{client: acmeClient, dns: godaddyClient, propagationWait: 30 * time.Second},
		godaddyClient,
		&configProviderAdapter{mgr: cfgMgr},
		logger,
	)

	// Start background cert renewal checker
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	certMgr.Start(runCtx)

	// Init and start admin API server
	adminAddr := fmt.Sprintf("%s:%d", cfg.Server.AdminHost, cfg.Server.AdminPort)
	apiServer := api.NewServer(cfgMgr, engine, acmeClient, godaddyClient, certMgr, logger)

	adminDone := make(chan error, 1)
	go func() { adminDone <- apiServer.Serve(runCtx, adminAddr) }()

	adminScheme := "http"
	if cfg.Security.AdminTLS.Enabled {
		adminScheme = "https"
	}
	logger.Info("ProxyGate running",
		"admin_ui", fmt.Sprintf("%s://%s", adminScheme, adminAddr),
		"http_proxy", fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		"https_proxy", fmt.Sprintf(":%d", cfg.Server.HTTPSPort),
	)

	// Run until asked to stop. An admin listener failure is logged but does
	// not take the proxy down, matching earlier behaviour.
	select {
	case <-ctx.Done():
	case err := <-adminDone:
		if err != nil {
			logger.Error("admin server stopped", "error", err)
		}
		<-ctx.Done()
	}

	logger.Info("shutting down...")
	cancel() // stop the cert checker and the admin listener
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()
	if err := engine.Stop(shutCtx); err != nil {
		logger.Error("proxy shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
	return 0
}
