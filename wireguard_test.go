package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInterfaceAddresses(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []netip.Addr
		wantErr bool
	}{
		{
			name:  "single IP address",
			input: "10.0.0.2",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name:  "single CIDR",
			input: "10.0.0.2/32",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name:  "multiple addresses",
			input: "10.0.0.2, 10.0.0.3",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")},
		},
		{
			name:  "mixed IP and CIDR",
			input: "10.0.0.2/32, 192.168.1.1",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.168.1.1")},
		},
		{
			name:  "IPv6",
			input: "fd00::1/128",
			want:  []netip.Addr{netip.MustParseAddr("fd00::1")},
		},
		{
			name:  "empty string defaults",
			input: "",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name:  "whitespace only defaults",
			input: "   ",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name:    "invalid address",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:  "mixed with empty entries",
			input: "10.0.0.2, , 10.0.0.3",
			want:  []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WireGuardConfig{Address: tt.input}
			got, err := cfg.parseInterfaceAddresses()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseDNSServers(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []netip.Addr
		wantErr bool
	}{
		{
			name:  "single DNS server",
			input: "8.8.8.8",
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		},
		{
			name:  "multiple DNS servers",
			input: "8.8.8.8, 8.8.4.4",
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
		},
		{
			name:  "IPv6 DNS",
			input: "2001:4860:4860::8888",
			want:  []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
		},
		{
			name:  "empty string defaults to Google DNS",
			input: "",
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
		},
		{
			name:    "invalid DNS server",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:  "mixed IPv4 and IPv6",
			input: "8.8.8.8, 2001:4860:4860::8888",
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")},
		},
		{
			name:  "with whitespace",
			input: "  8.8.8.8  ,  8.8.4.4  ",
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WireGuardConfig{DNSServers: tt.input}
			got, err := cfg.parseDNSServers()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildWireGuardConfig(t *testing.T) {
	// Valid test keys (base64-encoded 32-byte keys)
	validPrivateKey := "YJlw8hY1KE3nQjVhLZVLnY1l3sV4fXTqQJZQJqVLmXo="
	validPublicKey := "ZJlw8hY1KE3nQjVhLZVLnY1l3sV4fXTqQJZQJqVLmXo="
	validPresharedKey := "aJlw8hY1KE3nQjVhLZVLnY1l3sV4fXTqQJZQJqVLmXo="

	tests := []struct {
		name           string
		privateKey     string
		publicKey      string
		presharedKey   string
		endpoint       string
		allowedIPs     string
		wantErr        bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:         "valid config without PSK",
			privateKey:   validPrivateKey,
			publicKey:    validPublicKey,
			presharedKey: "",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantContains: []string{
				"private_key=",
				"public_key=",
				"endpoint=192.168.1.1:51820",
				"allowed_ip=0.0.0.0/0",
				"persistent_keepalive_interval=25",
			},
			wantNotContain: []string{"preshared_key="},
		},
		{
			name:         "valid config with PSK",
			privateKey:   validPrivateKey,
			publicKey:    validPublicKey,
			presharedKey: validPresharedKey,
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantContains: []string{
				"private_key=",
				"public_key=",
				"preshared_key=",
				"endpoint=192.168.1.1:51820",
				"allowed_ip=0.0.0.0/0",
			},
		},
		{
			name:         "multiple allowed IPs",
			privateKey:   validPrivateKey,
			publicKey:    validPublicKey,
			presharedKey: "",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "10.0.0.0/8, 192.168.0.0/16",
			wantContains: []string{
				"allowed_ip=10.0.0.0/8",
				"allowed_ip=192.168.0.0/16",
			},
		},
		{
			name:         "invalid private key",
			privateKey:   "not-base64",
			publicKey:    validPublicKey,
			presharedKey: "",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantErr:      true,
		},
		{
			name:         "invalid public key",
			privateKey:   validPrivateKey,
			publicKey:    "not-base64",
			presharedKey: "",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantErr:      true,
		},
		{
			name:         "wrong length private key",
			privateKey:   "YWJjZA==", // "abcd" in base64, only 4 bytes
			publicKey:    validPublicKey,
			presharedKey: "",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantErr:      true,
		},
		{
			name:         "wrong length preshared key",
			privateKey:   validPrivateKey,
			publicKey:    validPublicKey,
			presharedKey: "YWJjZA==",
			endpoint:     "192.168.1.1:51820",
			allowedIPs:   "0.0.0.0/0",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WireGuardConfig{
				PrivateKey:    tt.privateKey,
				PeerPublicKey: tt.publicKey,
				PresharedKey:  tt.presharedKey,
				AllowedIPs:    tt.allowedIPs,
			}
			got, err := cfg.buildConfig(tt.endpoint)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			for _, want := range tt.wantContains {
				assert.Contains(t, got, want)
			}
			for _, notWant := range tt.wantNotContain {
				assert.NotContains(t, got, notWant)
			}
		})
	}
}

func TestParseEndpointProtocols(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{name: "empty defaults to v4 then v6", input: "", want: []int{4, 6}},
		{name: "whitespace only defaults", input: "  ", want: []int{4, 6}},
		{name: "v4 first", input: "4,6", want: []int{4, 6}},
		{name: "v6 first", input: "6,4", want: []int{6, 4}},
		{name: "v4 only", input: "4", want: []int{4}},
		{name: "v6 only", input: "6", want: []int{6}},
		{name: "de-duplicates preserving order", input: "6,4,6", want: []int{6, 4}},
		{name: "trims and skips empties", input: " 4 , , 6 ", want: []int{4, 6}},
		{name: "invalid protocol", input: "4,5", wantErr: true},
		{name: "non-numeric", input: "ipv4", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WireGuardConfig{EndpointProtocols: tt.input}
			got, err := cfg.parseEndpointProtocols()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		protocols string
		want      []string
		wantErr   bool
	}{
		{name: "literal ipv4", endpoint: "192.168.1.1:51820", want: []string{"192.168.1.1:51820"}},
		{name: "literal ipv6", endpoint: "[2001:db8::1]:51820", want: []string{"[2001:db8::1]:51820"}},
		{name: "literal ipv4 excluded by protocols", endpoint: "192.168.1.1:51820", protocols: "6", wantErr: true},
		{name: "literal ipv6 excluded by protocols", endpoint: "[2001:db8::1]:51820", protocols: "4", wantErr: true},
		{name: "missing port", endpoint: "192.168.1.1", wantErr: true},
		{name: "empty endpoint", endpoint: "", wantErr: true},
		{name: "invalid protocols", endpoint: "192.168.1.1:51820", protocols: "9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &WireGuardConfig{Endpoint: tt.endpoint, EndpointProtocols: tt.protocols}
			got, err := cfg.resolveEndpoints()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOrderEndpoints(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("2001:db8::2"),
	}

	tests := []struct {
		name      string
		protocols []int
		want      []string
	}{
		{
			name:      "v4 first preserves dns order within protocol",
			protocols: []int{4, 6},
			want:      []string{"192.168.1.1:51820", "192.168.1.2:51820", "[2001:db8::1]:51820", "[2001:db8::2]:51820"},
		},
		{
			name:      "v6 first",
			protocols: []int{6, 4},
			want:      []string{"[2001:db8::1]:51820", "[2001:db8::2]:51820", "192.168.1.1:51820", "192.168.1.2:51820"},
		},
		{
			name:      "v4 only drops v6",
			protocols: []int{4},
			want:      []string{"192.168.1.1:51820", "192.168.1.2:51820"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, orderEndpoints(ips, "51820", tt.protocols))
		})
	}
}

func TestNextEndpoint(t *testing.T) {
	pool := []string{"a:1", "b:1", "c:1"}

	tests := []struct {
		name      string
		endpoints []string
		current   string
		want      string
	}{
		{name: "advances to next", endpoints: pool, current: "a:1", want: "b:1"},
		{name: "advances from middle", endpoints: pool, current: "b:1", want: "c:1"},
		{name: "wraps around at end", endpoints: pool, current: "c:1", want: "a:1"},
		{name: "current not present falls back to first", endpoints: pool, current: "z:1", want: "a:1"},
		{name: "single endpoint returns itself", endpoints: []string{"a:1"}, current: "a:1", want: "a:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, nextEndpoint(tt.endpoints, tt.current))
		})
	}
}
