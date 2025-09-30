package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// TailscaleNode manages the tsnet server and subnet routes
type TailscaleNode struct {
	server *tsnet.Server
	routes []netip.Prefix
}

// NewTailscaleNode creates a new Tailscale node with tsnet
func NewTailscaleNode(hostname, stateDir string) (*TailscaleNode, error) {
	server := &tsnet.Server{
		Hostname: hostname,
		Dir:      stateDir,
		UserLogf: func(format string, args ...any) {
			slog.Info(fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			slog.Debug(fmt.Sprintf(format, args...))
		},
	}

	return &TailscaleNode{
		server: server,
	}, nil
}

// RegisterTCPHandler registers a TCP handler for fallback connections
func (tn *TailscaleNode) RegisterTCPHandler(handler func(net.Conn, netip.AddrPort, netip.AddrPort)) {
	tn.server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return func(conn net.Conn) {
			handler(conn, src, dst)
		}, true
	})
}

// Start starts the Tailscale node
func (tn *TailscaleNode) Start(ctx context.Context) error {
	slog.Info("Starting Tailscale node", "hostname", tn.server.Hostname)

	_, err := tn.server.Up(ctx)
	if err != nil {
		return err
	}

	slog.Info("Tailscale node is up")
	return nil
}

// setAdvertisedRoutes updates the advertised routes via LocalClient
func (tn *TailscaleNode) setAdvertisedRoutes(ctx context.Context, routes []netip.Prefix) error {
	lc, err := tn.server.LocalClient()
	if err != nil {
		return err
	}

	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: routes,
			AppConnector: ipn.AppConnectorPrefs{
				Advertise: true,
			},
		},
		AdvertiseRoutesSet: true,
		AppConnectorSet:    true,
	})
	return err
}

// UpdateRoutes updates the advertised subnet routes dynamically
func (tn *TailscaleNode) UpdateRoutes(routes []netip.Prefix) {
	if !tn.routesDifferent(routes) {
		slog.Debug("Routes unchanged, skipping update")
		return
	}

	oldRoutes := tn.routes
	tn.routes = routes
	slog.Info("Updating routes", "count", len(routes))

	if err := tn.setAdvertisedRoutes(context.Background(), routes); err != nil {
		slog.Error("Failed to update routes", "error", err)
		tn.routes = oldRoutes // Rollback
		return
	}

	slog.Info("Successfully updated routes", "count", len(routes))
}

// routesDifferent returns true if newRoutes are different to the existing routes
func (tn *TailscaleNode) routesDifferent(newRoutes []netip.Prefix) bool {
	if len(tn.routes) != len(newRoutes) {
		return true
	}

	oldMap := make(map[netip.Prefix]bool)
	for _, r := range tn.routes {
		oldMap[r] = true
	}

	for _, r := range newRoutes {
		if !oldMap[r] {
			return true
		}
	}

	return false
}

// Close closes the Tailscale node
func (tn *TailscaleNode) Close() error {
	return tn.server.Close()
}
