package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// StartPeriodicResolver periodically re-resolves domains and updates the IP list
func StartPeriodicResolver(ctx context.Context, domains []string, interval time.Duration, updateFunc func([]netip.Prefix)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	resolveAndUpdate(ctx, domains, updateFunc)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolveAndUpdate(ctx, domains, updateFunc)
		}
	}
}

func resolveDomains(ctx context.Context, domains []string) ([]netip.Prefix, error) {
	ipMap := make(map[netip.Addr]bool)

	for _, domain := range domains {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
		if err != nil {
			slog.Warn("Failed to resolve domain", "domain", domain, "error", err)
			continue
		}

		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			ipMap[addr] = true
		}
	}

	prefixes := make([]netip.Prefix, 0, len(ipMap))
	for addr := range ipMap {
		var prefix netip.Prefix
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, 32)
		} else {
			prefix = netip.PrefixFrom(addr, 128)
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}

func resolveAndUpdate(ctx context.Context, domains []string, updateFunc func([]netip.Prefix)) {
	prefixes, err := resolveDomains(ctx, domains)
	if err != nil {
		slog.Error("Domain resolution failed", "error", err)
		return
	}
	slog.Info("Resolved IP addresses", "count", len(prefixes), "domains", len(domains))
	updateFunc(prefixes)
}
