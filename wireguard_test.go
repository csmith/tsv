package main

import (
	"net/netip"
	"testing"
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
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInterfaceAddresses() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parseInterfaceAddresses() got %d addresses, want %d", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("parseInterfaceAddresses() got[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDNSServers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parseDNSServers() got %d addresses, want %d", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("parseDNSServers() got[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
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
		{
			name:         "invalid endpoint format",
			privateKey:   validPrivateKey,
			publicKey:    validPublicKey,
			presharedKey: "",
			endpoint:     "invalid-endpoint",
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
				Endpoint:      tt.endpoint,
				AllowedIPs:    tt.allowedIPs,
			}
			got, err := cfg.buildConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("buildConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				for _, want := range tt.wantContains {
					if !contains(got, want) {
						t.Errorf("buildConfig() missing expected string %q in output:\n%s", want, got)
					}
				}
				for _, notWant := range tt.wantNotContain {
					if contains(got, notWant) {
						t.Errorf("buildConfig() contains unexpected string %q in output:\n%s", notWant, got)
					}
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
