package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

var (
	tsHostname  = flag.String("tailscale-hostname", "tsv", "Tailscale hostname")
	tsConfigDir = flag.String("tailscale-config-dir", "", "Directory to store tsnet state")
)

func ConnectToTailscale(ctx context.Context, connectionHandler func(net.Conn, netip.AddrPort, netip.AddrPort)) (*tsnet.Server, error) {
	server := &tsnet.Server{
		Hostname: *tsHostname,
		Dir:      *tsConfigDir,
		UserLogf: func(format string, args ...any) {
			slog.Info(fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			slog.Debug(fmt.Sprintf(format, args...))
		},
	}

	server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return func(conn net.Conn) {
			connectionHandler(conn, src, dst)
		}, true
	})

	slog.Info("Starting Tailscale node", "hostname", *tsHostname)

	_, err := server.Up(ctx)
	if err != nil {
		return nil, err
	}

	slog.Info("Tailscale node is up, advertising as AppConnector")

	lc, err := server.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get LocalClient: %w", err)
	}

	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{
				Advertise: true,
			},
			AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		AppConnectorSet:    true,
		AdvertiseRoutesSet: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to advertise as AppConnector: %w", err)
	}

	slog.Info("Successfully advertised as AppConnector")
	return server, nil
}
