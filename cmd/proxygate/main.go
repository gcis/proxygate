package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/api"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

var version = "dev"

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		configPath      = flag.String("config", "./data/proxygate.json", "Path to config file")
		showVersion     = flag.Bool("version", false, "Print version and exit")
		allowedNetworks multiFlag
	)
	flag.Var(&allowedNetworks, "allow-network", "Allow admin UI access from this CIDR (can be repeated)")
	flag.Parse()

	if *showVersion {
		fmt.Println("proxygate", version)
		os.Exit(0)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	logger.Info("starting ProxyGate", "version", version)

	// Load or create config
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
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
			os.Exit(1)
		}
		logger.Info("applied CLI network allowlist", "networks", []string(allowedNetworks))
	}

	cfg := cfgMgr.Get()

	// Init ACME client
	acmeClient, err := acme.NewClient(
		cfg.ACME.Email,
		cfg.ACME.CertDir,
		cfg.ACME.Directory,
		logger,
	)
	if err != nil {
		logger.Error("failed to init ACME client", "error", err)
		os.Exit(1)
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
		os.Exit(1)
	}

	// Init and start admin API server
	adminAddr := fmt.Sprintf("%s:%d", cfg.Server.AdminHost, cfg.Server.AdminPort)
	apiServer := api.NewServer(cfgMgr, engine, acmeClient, godaddyClient, logger)

	go func() {
		if err := apiServer.Start(adminAddr); err != nil {
			logger.Error("admin server stopped", "error", err)
		}
	}()

	logger.Info("ProxyGate running",
		"admin_ui", fmt.Sprintf("http://%s", adminAddr),
		"http_proxy", fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		"https_proxy", fmt.Sprintf(":%d", cfg.Server.HTTPSPort),
	)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := engine.Stop(ctx); err != nil {
		logger.Error("proxy shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
}
