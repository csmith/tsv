package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
)

func main() {
	envflag.Parse()
	slogflags.Logger(slogflags.WithSetDefault(true))

	if err := validateFlags(); err != nil {
		slog.Error("Flag validation failed", "error", err)
		os.Exit(1)
	}

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

	wgClient, err := NewWireGuardClient()
	if err != nil {
		slog.Error("Failed to create WireGuard client", "error", err)
		os.Exit(1)
	}
	defer wgClient.Close()

	proxy := NewProxy(wgClient, ctx)

	ts, err := ConnectToTailscale(ctx, proxy.HandleConnection)
	if err != nil {
		slog.Error("Failed to start Tailscale node", "error", err)
		os.Exit(1)
	}
	defer ts.Close()

	slog.Info("Tailscale VPN node is running")

	<-ctx.Done()
	slog.Info("Shutdown complete")
}

func validateFlags() error {
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
