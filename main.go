package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
)

var (
	// Tailscale
	tsHostname  = flag.String("tailscale-hostname", "tsv", "Tailscale hostname")
	tsConfigDir = flag.String("tailscale-config-dir", "", "Directory to store tsnet state")

	// DNS
	domains       = flag.String("domains", "", "Comma or space-separated list of domains to route")
	resolvePeriod = flag.Duration("resolve-period", 6*time.Hour, "How often to re-resolve domains")

	// WireGuard
	wgPrivateKey        = flag.String("wg-private-key", "", "WireGuard private key (base64 encoded string)")
	wgPublicKey         = flag.String("wg-public-key", "", "WireGuard peer public key (base64 encoded string)")
	wgPresharedKey      = flag.String("wg-preshared-key", "", "WireGuard preshared key (optional; base64 encoded string)")
	wgEndpoint          = flag.String("wg-endpoint", "", "WireGuard endpoint (host:port; dns names resolved at startup)")
	wgAllowedIPs        = flag.String("wg-allowed-ips", "0.0.0.0/0,::/0", "WireGuard allowed IPs (comma-separated)")
	wgAddress           = flag.String("wg-address", "", "WireGuard interface address (e.g., 10.0.0.2/32)")
	wgDNS               = flag.String("wg-dns", "9.9.9.9", "DNS servers (comma-separated)")
	wgMTU               = flag.Int("wg-mtu", 1420, "WireGuard MTU")
	wgHealthCheckURL    = flag.String("wg-health-check-url", "https://www.gstatic.com/generate_204", "Health check URL")
	wgHealthCheckPeriod = flag.Duration("wg-health-check-period", 30*time.Second, "Health check period")
)

func main() {
	envflag.Parse()
	slogflags.Logger(slogflags.WithSetDefault(true))

	if err := validateFlags(); err != nil {
		slog.Error("Flag validation failed", "error", err)
		os.Exit(1)
	}

	domainList := parseDomains(*domains)
	slog.Info("Domains to route", "domains", domainList)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutting down...")
		cancel()
	}()

	slog.Info("Starting Tailscale VPN node...")

	wgClient, err := NewWireGuardClient(&WireGuardConfig{
		PrivateKey:        *wgPrivateKey,
		PeerPublicKey:     *wgPublicKey,
		PresharedKey:      *wgPresharedKey,
		Endpoint:          *wgEndpoint,
		AllowedIPs:        *wgAllowedIPs,
		Address:           *wgAddress,
		DNSServers:        *wgDNS,
		MTU:               *wgMTU,
		HealthCheckURL:    *wgHealthCheckURL,
		HealthCheckPeriod: *wgHealthCheckPeriod,
	})
	if err != nil {
		slog.Error("Failed to create WireGuard client", "error", err)
		os.Exit(1)
	}
	defer wgClient.Close()

	tsNode, err := NewTailscaleNode(*tsHostname, *tsConfigDir)
	if err != nil {
		slog.Error("Failed to create Tailscale node", "error", err)
		os.Exit(1)
	}
	defer tsNode.Close()

	err = tsNode.Start(ctx)
	if err != nil {
		slog.Error("Failed to start Tailscale node", "error", err)
		os.Exit(1)
	}

	go StartPeriodicResolver(ctx, domainList, *resolvePeriod, tsNode.UpdateRoutes)

	proxy := NewProxy(tsNode, wgClient, ctx)
	proxy.Start()

	slog.Info("Tailscale VPN node is running")

	<-ctx.Done()
	slog.Info("Shutdown complete")
}

func validateFlags() error {
	if *domains == "" {
		return fmt.Errorf("--domains is required")
	}
	if *wgPrivateKey == "" {
		return fmt.Errorf("--wg-private-key is required")
	}
	if *wgPublicKey == "" {
		return fmt.Errorf("--wg-public-key is required")
	}
	if *wgEndpoint == "" {
		return fmt.Errorf("--wg-endpoint is required")
	}
	return nil
}

func parseDomains(domainsStr string) []string {
	var whitespaceRegex = regexp.MustCompile(`\s+`)
	parts := strings.Split(whitespaceRegex.ReplaceAllString(domainsStr, ","), ",")
	res := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			res = append(res, d)
		}
	}
	return res
}
