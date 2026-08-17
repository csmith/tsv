package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	wgPrivateKey        = flag.String("wg-private-key", "", "WireGuard private key (base64 encoded string)")
	wgPublicKey         = flag.String("wg-public-key", "", "WireGuard peer public key (base64 encoded string)")
	wgPresharedKey      = flag.String("wg-preshared-key", "", "WireGuard preshared key (optional; base64 encoded string)")
	wgEndpoint          = flag.String("wg-endpoint", "", "WireGuard endpoint (host:port; hostnames are re-resolved and round-robined on failure)")
	wgEndpointProtocols = flag.String("wg-endpoint-protocols", "4,6", "IP protocols to use for the endpoint, in preference order (comma-separated: 4, 6)")
	wgAllowedIPs        = flag.String("wg-allowed-ips", "0.0.0.0/0,::/0", "WireGuard allowed IPs (comma-separated)")
	wgAddress           = flag.String("wg-address", "", "WireGuard interface address (e.g., 10.0.0.2/32)")
	wgDNS               = flag.String("wg-dns", "9.9.9.9", "DNS servers (comma-separated)")
	wgMTU               = flag.Int("wg-mtu", 1420, "WireGuard MTU")
	wgHealthCheckURL    = flag.String("wg-health-check-url", "https://www.gstatic.com/generate_204", "Health check URL")
	wgHealthCheckPeriod = flag.Duration("wg-health-check-period", 30*time.Second, "Health check period")
)

// WireGuardClient manages a userland WireGuard connection
type WireGuardClient struct {
	dev               *device.Device
	tun               *netstack.Net
	cfg               *WireGuardConfig
	peerPublicKeyHex  string
	ctx               context.Context
	cancel            context.CancelFunc
	healthCheckURL    string
	healthCheckPeriod time.Duration

	// currentEndpoint, failureCount and consecutiveFailures are only touched
	// by the healthCheck goroutine, so they need no synchronisation.
	currentEndpoint     string
	failureCount        int
	consecutiveFailures int
}

// NewWireGuardClient creates a new userland WireGuard client
func NewWireGuardClient() (*WireGuardClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cfg := &WireGuardConfig{
		PrivateKey:        *wgPrivateKey,
		PeerPublicKey:     *wgPublicKey,
		PresharedKey:      *wgPresharedKey,
		Endpoint:          *wgEndpoint,
		EndpointProtocols: *wgEndpointProtocols,
		AllowedIPs:        *wgAllowedIPs,
		Address:           *wgAddress,
		DNSServers:        *wgDNS,
		MTU:               *wgMTU,
		HealthCheckURL:    *wgHealthCheckURL,
		HealthCheckPeriod: *wgHealthCheckPeriod,
	}

	peerPublicKeyHex, err := decodeKey("public key", cfg.PeerPublicKey)
	if err != nil {
		cancel()
		return nil, err
	}

	dev, tnet, endpoint, err := cfg.createNetTUN()
	if err != nil {
		cancel()
		return nil, err
	}

	healthCheckURL := cfg.HealthCheckURL
	if healthCheckURL == "" {
		healthCheckURL = "https://www.gstatic.com/generate_204"
	}
	healthCheckPeriod := cfg.HealthCheckPeriod
	if healthCheckPeriod == 0 {
		healthCheckPeriod = 30 * time.Second
	}

	wgClient := &WireGuardClient{
		dev:               dev,
		tun:               tnet,
		cfg:               cfg,
		peerPublicKeyHex:  peerPublicKeyHex,
		ctx:               ctx,
		cancel:            cancel,
		healthCheckURL:    healthCheckURL,
		healthCheckPeriod: healthCheckPeriod,
		currentEndpoint:   endpoint,
	}

	go wgClient.healthCheck()

	return wgClient, nil
}

// Dial creates a connection through the WireGuard tunnel
func (wg *WireGuardClient) Dial(network, address string) (net.Conn, error) {
	return wg.tun.Dial(network, address)
}

// DialContext creates a connection through the WireGuard tunnel with context
func (wg *WireGuardClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return wg.tun.DialContext(ctx, network, address)
}

// healthCheck periodically checks WireGuard connectivity
func (wg *WireGuardClient) healthCheck() {
	ticker := time.NewTicker(wg.healthCheckPeriod)
	defer ticker.Stop()

	if !wg.checkConnectivity() {
		wg.consecutiveFailures++
		wg.failureCount++
	} else {
		wg.consecutiveFailures = 0
	}

	for {
		select {
		case <-wg.ctx.Done():
			return
		case <-ticker.C:
			if !wg.checkConnectivity() {
				wg.consecutiveFailures++
				wg.failureCount++

				if wg.consecutiveFailures >= 3 {
					slog.Error("WireGuard health check failed 3 consecutive times, attempting to restart device",
						"total_failures", wg.failureCount,
						"consecutive_failures", wg.consecutiveFailures)
					wg.restartDevice()
				}
			} else {
				wg.consecutiveFailures = 0
			}
		}
	}
}

// restartDevice attempts to restart the WireGuard device. If the endpoint is a
// hostname it first re-resolves it and rotates to the next address in the pool,
// so that a single dead pool member is routed around.
func (wg *WireGuardClient) restartDevice() {
	slog.Info("Restarting WireGuard device...")

	if err := wg.rotateEndpoint(); err != nil {
		slog.Error("Failed to rotate WireGuard endpoint, keeping current endpoint",
			"endpoint", wg.currentEndpoint, "error", err)
	}

	wg.dev.Down()
	time.Sleep(1 * time.Second)
	wg.dev.Up()

	wg.consecutiveFailures = 0

	slog.Info("WireGuard device restarted", "endpoint", wg.currentEndpoint)
}

// rotateEndpoint re-resolves the endpoint hostname (a fresh DNS query every
// time, so we never act on stale data) and points the peer at the next address
// in the pool. For a literal IP or single-address hostname this is effectively
// a no-op beyond picking up DNS changes.
func (wg *WireGuardClient) rotateEndpoint() error {
	endpoints, err := wg.cfg.resolveEndpoints()
	if err != nil {
		return err
	}

	next := nextEndpoint(endpoints, wg.currentEndpoint)
	if next == wg.currentEndpoint {
		slog.Debug("Endpoint unchanged after re-resolving", "endpoint", next, "candidates", len(endpoints))
		return nil
	}

	if err := wg.dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", wg.peerPublicKeyHex, next)); err != nil {
		return fmt.Errorf("failed to update peer endpoint: %w", err)
	}

	slog.Info("Rotated WireGuard endpoint", "from", wg.currentEndpoint, "to", next, "candidates", len(endpoints))
	wg.currentEndpoint = next
	return nil
}

// nextEndpoint returns the endpoint following current in the list, wrapping
// around at the end. If current is not present (e.g. DNS returned an entirely
// different set of addresses) the first endpoint is returned. endpoints must
// not be empty.
func nextEndpoint(endpoints []string, current string) string {
	for i, ep := range endpoints {
		if ep == current {
			return endpoints[(i+1)%len(endpoints)]
		}
	}
	return endpoints[0]
}

// checkConnectivity tests if we can reach the internet through WireGuard
// Returns true if the check passed, false otherwise
func (wg *WireGuardClient) checkConnectivity() bool {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return wg.tun.DialContext(ctx, network, addr)
			},
		},
		Timeout: 10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(wg.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", wg.healthCheckURL, nil)
	if err != nil {
		slog.Error("Failed to create health check request", "error", err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("WireGuard health check failed", "error", err, "url", wg.healthCheckURL)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 || resp.StatusCode == 200 {
		slog.Debug("WireGuard health check passed", "url", wg.healthCheckURL, "status", resp.StatusCode)
		return true
	}

	slog.Warn("WireGuard health check unexpected status", "url", wg.healthCheckURL, "status", resp.StatusCode)
	return false
}

// Close closes the WireGuard client
func (wg *WireGuardClient) Close() error {
	wg.cancel()
	wg.dev.Close()
	return nil
}

// WireGuardConfig holds the configuration for a WireGuard connection
type WireGuardConfig struct {
	PrivateKey        string
	PeerPublicKey     string
	PresharedKey      string
	Endpoint          string
	EndpointProtocols string
	AllowedIPs        string
	Address           string
	DNSServers        string
	MTU               int
	HealthCheckURL    string
	HealthCheckPeriod time.Duration
}

// parseInterfaceAddresses parses comma-separated interface addresses
func (cfg *WireGuardConfig) parseInterfaceAddresses() ([]netip.Addr, error) {
	address := cfg.Address
	var ifaceAddrs []netip.Addr
	if address != "" {
		addrStrings := strings.SplitSeq(address, ",")
		for addrStr := range addrStrings {
			addrStr = strings.TrimSpace(addrStr)
			if addrStr == "" {
				continue
			}

			prefix, err := netip.ParsePrefix(addrStr)
			if err != nil {
				addr, err := netip.ParseAddr(addrStr)
				if err != nil {
					return nil, fmt.Errorf("invalid interface address %s: %w", addrStr, err)
				}
				ifaceAddrs = append(ifaceAddrs, addr)
			} else {
				ifaceAddrs = append(ifaceAddrs, prefix.Addr())
			}
		}
	}

	if len(ifaceAddrs) == 0 {
		ifaceAddrs = []netip.Addr{netip.MustParseAddr("10.0.0.2")}
	}

	return ifaceAddrs, nil
}

// parseDNSServers parses comma-separated DNS server addresses
func (cfg *WireGuardConfig) parseDNSServers() ([]netip.Addr, error) {
	dnsServers := cfg.DNSServers
	var dnsAddrs []netip.Addr
	if dnsServers != "" {
		dnsStrings := strings.SplitSeq(dnsServers, ",")
		for dnsStr := range dnsStrings {
			dnsStr = strings.TrimSpace(dnsStr)
			addr, err := netip.ParseAddr(dnsStr)
			if err != nil {
				return nil, fmt.Errorf("invalid DNS server %s: %w", dnsStr, err)
			}
			dnsAddrs = append(dnsAddrs, addr)
		}
	} else {
		dnsAddrs = []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		}
	}

	return dnsAddrs, nil
}

// parseEndpointProtocols parses the comma-separated protocol preference list
// (e.g. "4,6") into an ordered, de-duplicated list of IP versions. An empty
// value defaults to IPv4 first, then IPv6.
func (cfg *WireGuardConfig) parseEndpointProtocols() ([]int, error) {
	if strings.TrimSpace(cfg.EndpointProtocols) == "" {
		return []int{4, 6}, nil
	}

	var protocols []int
	seen := make(map[int]bool)
	for p := range strings.SplitSeq(cfg.EndpointProtocols, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var version int
		switch p {
		case "4":
			version = 4
		case "6":
			version = 6
		default:
			return nil, fmt.Errorf("invalid endpoint protocol %q (must be 4 or 6)", p)
		}
		if !seen[version] {
			seen[version] = true
			protocols = append(protocols, version)
		}
	}

	if len(protocols) == 0 {
		return nil, fmt.Errorf("no valid endpoint protocols specified")
	}
	return protocols, nil
}

// resolveEndpoints resolves the endpoint host to a list of ip:port endpoints,
// ordered by the configured protocol preference. Hostnames are looked up fresh
// on every call (no caching) so that round-robin pools and failover changes are
// always reflected. A literal IP address is returned as-is, provided its
// protocol is permitted.
func (cfg *WireGuardConfig) resolveEndpoints() ([]string, error) {
	host, port, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint format: %w", err)
	}

	protocols, err := cfg.parseEndpointProtocols()
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if !protocolAllowed(protocols, ip) {
			return nil, fmt.Errorf("endpoint %s is not permitted by the configured protocols %v", host, protocols)
		}
		return []string{cfg.Endpoint}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %s: %w", host, err)
	}

	endpoints := orderEndpoints(ips, port, protocols)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no usable IPs found for hostname %s with protocols %v", host, protocols)
	}

	slog.Debug("Resolved WireGuard endpoint", "hostname", host, "endpoints", endpoints)
	return endpoints, nil
}

// orderEndpoints groups the resolved IPs by protocol version and returns
// ip:port endpoints ordered according to the protocol preference list. Within a
// protocol the DNS ordering is preserved. IPs whose protocol is not in the
// preference list are dropped.
func orderEndpoints(ips []net.IP, port string, protocols []int) []string {
	var endpoints []string
	for _, version := range protocols {
		for _, ip := range ips {
			if ipVersion(ip) == version {
				endpoints = append(endpoints, net.JoinHostPort(ip.String(), port))
			}
		}
	}
	return endpoints
}

// ipVersion returns 4 for an IPv4 address and 6 for an IPv6 address.
func ipVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// protocolAllowed reports whether the given IP's protocol is in the list.
func protocolAllowed(protocols []int, ip net.IP) bool {
	target := ipVersion(ip)
	return slices.Contains(protocols, target)
}

// createNetTUN creates a netstack TUN device with parsed addresses. It returns
// the endpoint the peer was initially configured with, so the caller can track
// it for later rotation.
func (cfg *WireGuardConfig) createNetTUN() (*device.Device, *netstack.Net, string, error) {
	ifaceAddrs, err := cfg.parseInterfaceAddresses()
	if err != nil {
		return nil, nil, "", err
	}

	dnsAddrs, err := cfg.parseDNSServers()
	if err != nil {
		return nil, nil, "", err
	}

	endpoints, err := cfg.resolveEndpoints()
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to resolve endpoint: %w", err)
	}
	endpoint := endpoints[0]

	tun, tnet, err := netstack.CreateNetTUN(ifaceAddrs, dnsAddrs, cfg.MTU)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create TUN: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	config, err := cfg.buildConfig(endpoint)
	if err != nil {
		dev.Close()
		return nil, nil, "", fmt.Errorf("failed to build config: %w", err)
	}

	if err := dev.IpcSet(config); err != nil {
		dev.Close()
		return nil, nil, "", fmt.Errorf("failed to configure device: %w", err)
	}

	dev.Up()
	slog.Info("WireGuard device is up", "dns_servers", dnsAddrs, "endpoint", endpoint)

	return dev, tnet, endpoint, nil
}

// decodeKey decodes a base64-encoded WireGuard key and returns its hex
// encoding, validating that it is exactly 32 bytes. name is used in errors.
func decodeKey(name, key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", name, err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("%s must be 32 bytes", name)
	}
	return hex.EncodeToString(raw), nil
}

// buildConfig creates the WireGuard configuration string for the given endpoint.
func (cfg *WireGuardConfig) buildConfig(endpoint string) (string, error) {
	privKeyHex, err := decodeKey("private key", cfg.PrivateKey)
	if err != nil {
		return "", err
	}

	pubKeyHex, err := decodeKey("public key", cfg.PeerPublicKey)
	if err != nil {
		return "", err
	}

	var pskHex string
	if cfg.PresharedKey != "" {
		pskHex, err = decodeKey("preshared key", cfg.PresharedKey)
		if err != nil {
			return "", err
		}
	}

	allowedIPList := strings.Split(cfg.AllowedIPs, ",")
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", privKeyHex))
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", pubKeyHex))

	if pskHex != "" {
		configBuilder.WriteString(fmt.Sprintf("preshared_key=%s\n", pskHex))
	}

	configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", endpoint))

	for _, ip := range allowedIPList {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}

	configBuilder.WriteString("persistent_keepalive_interval=25\n")

	return configBuilder.String(), nil
}
