package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuardClient manages a userland WireGuard connection
type WireGuardClient struct {
	dev                 *device.Device
	tun                 *netstack.Net
	ctx                 context.Context
	cancel              context.CancelFunc
	healthCheckURL      string
	healthCheckPeriod   time.Duration
	failureCount        int
	consecutiveFailures int
}

// NewWireGuardClient creates a new userland WireGuard client
func NewWireGuardClient(cfg *WireGuardConfig) (*WireGuardClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	dev, tnet, err := cfg.createNetTUN()
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
		ctx:               ctx,
		cancel:            cancel,
		healthCheckURL:    healthCheckURL,
		healthCheckPeriod: healthCheckPeriod,
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

// restartDevice attempts to restart the WireGuard device
func (wg *WireGuardClient) restartDevice() {
	slog.Info("Restarting WireGuard device...")

	wg.dev.Down()
	time.Sleep(1 * time.Second)
	wg.dev.Up()

	wg.consecutiveFailures = 0

	slog.Info("WireGuard device restarted")
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
		addrStrings := strings.Split(address, ",")
		for _, addrStr := range addrStrings {
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
		dnsStrings := strings.Split(dnsServers, ",")
		for _, dnsStr := range dnsStrings {
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

// resolveEndpoint resolves the endpoint hostname to IP:port
func (cfg *WireGuardConfig) resolveEndpoint() (string, error) {
	host, port, err := net.SplitHostPort(cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint format: %w", err)
	}

	if ip := net.ParseIP(host); ip != nil {
		return cfg.Endpoint, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for hostname %s", host)
	}

	// Prefer IPv4 if available
	var selectedIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			selectedIP = ip
			break
		}
	}
	if selectedIP == nil {
		selectedIP = ips[0]
	}

	resolvedEndpoint := net.JoinHostPort(selectedIP.String(), port)
	slog.Info("Resolved WireGuard endpoint", "hostname", host, "ip", selectedIP.String(), "endpoint", resolvedEndpoint)
	return resolvedEndpoint, nil
}

// createNetTUN creates a netstack TUN device with parsed addresses
func (cfg *WireGuardConfig) createNetTUN() (*device.Device, *netstack.Net, error) {
	ifaceAddrs, err := cfg.parseInterfaceAddresses()
	if err != nil {
		return nil, nil, err
	}

	dnsAddrs, err := cfg.parseDNSServers()
	if err != nil {
		return nil, nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(ifaceAddrs, dnsAddrs, cfg.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	config, err := cfg.buildConfig()
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to build config: %w", err)
	}

	if err := dev.IpcSet(config); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to configure device: %w", err)
	}

	dev.Up()
	slog.Info("WireGuard device is up", "dns_servers", dnsAddrs)

	return dev, tnet, nil
}

// buildConfig creates the WireGuard configuration string
func (cfg *WireGuardConfig) buildConfig() (string, error) {
	privKey, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	if len(privKey) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}
	privKeyHex := hex.EncodeToString(privKey)

	pubKey, err := base64.StdEncoding.DecodeString(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	if len(pubKey) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes")
	}
	pubKeyHex := hex.EncodeToString(pubKey)

	var pskHex string
	if cfg.PresharedKey != "" {
		psk, err := base64.StdEncoding.DecodeString(cfg.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("invalid preshared key: %w", err)
		}
		if len(psk) != 32 {
			return "", fmt.Errorf("preshared key must be 32 bytes")
		}
		pskHex = hex.EncodeToString(psk)
	}

	resolvedEndpoint, err := cfg.resolveEndpoint()
	if err != nil {
		return "", fmt.Errorf("failed to resolve endpoint: %w", err)
	}

	allowedIPList := strings.Split(cfg.AllowedIPs, ",")
	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", privKeyHex))
	configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", pubKeyHex))

	if pskHex != "" {
		configBuilder.WriteString(fmt.Sprintf("preshared_key=%s\n", pskHex))
	}

	configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", resolvedEndpoint))

	for _, ip := range allowedIPList {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
	}

	configBuilder.WriteString("persistent_keepalive_interval=25\n")

	return configBuilder.String(), nil
}
