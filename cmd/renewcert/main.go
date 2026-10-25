// Command renewcert performs a one-shot ACME DNS-01 renewal for one or more
// domains using the same config, account key and GoDaddy credentials as the
// proxygate daemon. It writes the new cert/key into the configured cert dir.
// The running daemon reloads certs from disk on any route update (e.g. a
// PUT /api/routes/{id} via the admin API), so no listener restart is needed.
//
// Usage: renewcert [-config ./data/proxygate.json] domain [domain...]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
)

func main() {
	configPath := flag.String("config", "./data/proxygate.json", "Path to config file")
	wait := flag.Duration("propagation-wait", 30*time.Second, "Wait after creating the TXT record")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: renewcert [-config path] domain [domain...]")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg := cfgMgr.Get()

	acmeClient, err := acme.NewClient(cfg.ACME.Email, cfg.ACME.CertDir, cfg.ACME.Directory, logger)
	if err != nil {
		logger.Error("failed to init ACME client", "error", err)
		os.Exit(1)
	}
	dns := godaddy.NewClient(cfg.GoDaddy.APIKey, cfg.GoDaddy.APISecret, cfg.GoDaddy.BaseURL, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := acmeClient.Register(ctx); err != nil {
		logger.Error("acme register failed", "error", err)
		os.Exit(1)
	}

	failed := 0
	for _, domain := range flag.Args() {
		if err := renew(ctx, acmeClient, dns, domain, *wait); err != nil {
			logger.Error("renewal failed", "domain", domain, "error", err)
			failed++
			continue
		}
		logger.Info("renewal succeeded", "domain", domain)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func renew(ctx context.Context, c *acme.Client, dns acme.DNSProvider, domain string, wait time.Duration) error {
	status, err := c.RequestCertificate(ctx, domain)
	if err != nil {
		return fmt.Errorf("acme request: %w", err)
	}
	if err := dns.CreateTXTRecord(ctx, domain, status.RecordName, status.RecordVal); err != nil {
		return fmt.Errorf("creating TXT record: %w", err)
	}
	time.Sleep(wait)
	_, _, err = c.CompleteChallengeAndFetchCert(ctx, domain)
	return err
}
