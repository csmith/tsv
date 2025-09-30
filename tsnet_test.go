package main

import (
	"net/netip"
	"testing"
)

func TestRoutesDifferent(t *testing.T) {
	tests := []struct {
		name       string
		oldRoutes  []netip.Prefix
		newRoutes  []netip.Prefix
		wantResult bool
	}{
		{
			name:       "empty to empty",
			oldRoutes:  []netip.Prefix{},
			newRoutes:  []netip.Prefix{},
			wantResult: false,
		},
		{
			name:      "empty to non-empty",
			oldRoutes: []netip.Prefix{},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantResult: true,
		},
		{
			name: "non-empty to empty",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			newRoutes:  []netip.Prefix{},
			wantResult: true,
		},
		{
			name: "identical routes",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantResult: false,
		},
		{
			name: "identical routes different order",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantResult: false,
		},
		{
			name: "different routes same count",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			wantResult: true,
		},
		{
			name: "added route",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			wantResult: true,
		},
		{
			name: "removed route",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantResult: true,
		},
		{
			name: "IPv6 routes",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("fd00::/64"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("fd00::/64"),
			},
			wantResult: false,
		},
		{
			name: "mixed IPv4 and IPv6",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("fd00::/64"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("fd00::/64"),
			},
			wantResult: false,
		},
		{
			name: "completely different routes",
			oldRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
			},
			newRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("fd00::/8"),
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tn := &TailscaleNode{
				routes: tt.oldRoutes,
			}
			got := tn.routesDifferent(tt.newRoutes)
			if got != tt.wantResult {
				t.Errorf("routesDifferent() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}
