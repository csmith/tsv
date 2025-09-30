package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Proxy handles proxying connections to WireGuard
type Proxy struct {
	wgClient *WireGuardClient
	ctx      context.Context
}

// NewProxy creates a new proxy
func NewProxy(wgClient *WireGuardClient, ctx context.Context) *Proxy {
	return &Proxy{
		wgClient: wgClient,
		ctx:      ctx,
	}
}

func (p *Proxy) HandleConnection(clientConn net.Conn, src, dst netip.AddrPort) {
	defer clientConn.Close()

	destAddr := dst.String()
	srcAddr := src.String()

	slog.Debug("Connection opened", "destination", destAddr, "source", srcAddr)

	dialCtx, dialCancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer dialCancel()

	serverConn, err := p.wgClient.DialContext(dialCtx, "tcp", destAddr)
	if err != nil {
		slog.Error("Failed to dial through WireGuard", "destination", destAddr, "source", srcAddr, "error", err)
		return
	}
	defer func() {
		serverConn.Close()
		slog.Debug("Connection closed", "destination", destAddr, "source", srcAddr)
	}()

	slog.Debug("Connected to destination via WireGuard", "destination", destAddr, "source", srcAddr)

	if tcpConn, ok := serverConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetNoDelay(true)
	}
	if setter, ok := clientConn.(interface{ SetNoDelay(bool) error }); ok {
		_ = setter.SetNoDelay(true)
	}

	done := make(chan struct{})

	go func() {
		if _, err := io.Copy(serverConn, clientConn); err != nil {
			slog.Debug("Client to server copy error", "destination", destAddr, "source", srcAddr, "error", err)
		}
		if closer, ok := serverConn.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}()

	go func() {
		defer close(done)
		if _, err := io.Copy(clientConn, serverConn); err != nil {
			slog.Debug("Server to client copy error", "destination", destAddr, "source", srcAddr, "error", err)
		}
		if closer, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Minute):
		slog.Debug("Connection idle timeout", "destination", destAddr, "source", srcAddr)
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
}
