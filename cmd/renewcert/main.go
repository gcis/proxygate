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
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run renews each domain named in args and returns the exit code: 0 if all
// succeeded, 1 on any failure, 2 on usage errors.
func run(parent context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("renewcert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "./data/proxygate.json", "Path to config file")
	wait := fs.Duration("propagation-wait", 30*time.Second, "Wait after creating the TXT record")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: renewcert [-config path] domain [domain...]")
		return 2
	}

	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		return 1
	}
	cfg := cfgMgr.Get()

	acmeClient, err := acme.NewClient(cfg.ACME.Email, cfg.ACME.CertDir, cfg.ACME.Directory, logger)
	if err != nil {
		logger.Error("failed to init ACME client", "error", err)
		return 1
	}
	dns := godaddy.NewClient(cfg.GoDaddy.APIKey, cfg.GoDaddy.APISecret, cfg.GoDaddy.BaseURL, logger)

	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	if err := acmeClient.Register(ctx); err != nil {
		logger.Error("acme register failed", "error", err)
		return 1
	}

	failed := 0
	for _, domain := range fs.Args() {
		if err := renew(ctx, acmeClient, dns, domain, *wait); err != nil {
			logger.Error("renewal failed", "domain", domain, "error", err)
			failed++
			continue
		}
		logger.Info("renewal succeeded", "domain", domain)
	}
	if failed > 0 {
		return 1
	}
	return 0
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
