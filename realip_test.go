package realip_test

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/tetsuo/realip"
)

func TestNewDefaultOptions(t *testing.T) {
	rip := realip.New()
	if rip == nil {
		t.Fatal("New() returned nil")
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	got := rip.FromRequest(req)
	if got != "192.168.1.100" {
		t.Errorf("FromRequest() = %q, want %q", got, "192.168.1.100")
	}
}

func TestFromRequestDefaultConfig(t *testing.T) {
	rip := realip.New()
	// Configure headers with Set methods
	rip.SetHeaders([]string{realip.XForwardedFor, realip.XRealIP, realip.TrueClientIP})

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no headers, uses remote addr",
			remoteAddr: "192.168.1.100:54321",
			headers:    map[string]string{},
			want:       "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195"},
			want:       "203.0.113.195",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Real-IP": "198.51.100.178"},
			want:       "198.51.100.178",
		},
		{
			name:       "True-Client-IP header",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"True-Client-IP": "192.0.2.60"},
			want:       "192.0.2.60",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195",
				"X-Real-IP":       "198.51.100.178",
			},
			want: "203.0.113.195",
		},
		{
			name:       "fallback to remote addr when invalid IP",
			remoteAddr: "192.168.1.100:54321",
			headers:    map[string]string{"X-Forwarded-For": "invalid"},
			want:       "192.168.1.100",
		},
		{
			name:       "fallback to empty string when no info",
			remoteAddr: "",
			headers:    map[string]string{},
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			// Trust the peer to allow header parsing
			if tt.remoteAddr != "" {
				addrPort, err := netip.ParseAddrPort(tt.remoteAddr)
				if err == nil {
					rip.SetTrustedPeers([]netip.Prefix{netip.PrefixFrom(addrPort.Addr(), addrPort.Addr().BitLen())})
				} else {
					// Handle cases where remoteAddr is just IP or invalid
					ipAddr, err := netip.ParseAddr(tt.remoteAddr)
					if err == nil {
						rip.SetTrustedPeers([]netip.Prefix{netip.PrefixFrom(ipAddr, ipAddr.BitLen())})
					} else {
						rip.SetTrustedPeers(nil)
					}
				}
			} else {
				rip.SetTrustedPeers(nil)
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestXForwardedForMultipleIPs(t *testing.T) {
	trustedPeer, _ := netip.ParsePrefix("10.0.0.1/32")

	tests := []struct {
		name       string
		remoteAddr string
		xffValue   string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "multiple IPs in X-Forwarded-For, rightmost non-proxied",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195, 70.41.3.18, 150.172.238.178",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
			},
			want: "150.172.238.178",
		},
		{
			name:       "multiple IPs with ProxyCnt=1, skip last",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195, 70.41.3.18, 150.172.238.178",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithProxyCnt(1),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
			},
			want: "70.41.3.18",
		},
		{
			name:       "multiple IPs with ProxyCnt=2",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195, 70.41.3.18, 150.172.238.178",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithProxyCnt(2),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
			},
			want: "203.0.113.195",
		},
		{
			name:       "ProxyCnt larger than available IPs",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195, 70.41.3.18",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithProxyCnt(5),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
			},
			want: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-For", tt.xffValue)

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestTrustedProxies(t *testing.T) {
	// Parse trusted proxy networks
	trustedNet, _ := netip.ParsePrefix("10.0.0.0/8")

	tests := []struct {
		name       string
		remoteAddr string
		xffValue   string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "with trusted proxies, gets rightmost non-proxy IP",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195, 70.41.3.18",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedProxies([]netip.Prefix{trustedNet}),
				realip.WithTrustedPeers([]netip.Prefix{trustedNet}),
			},
			want: "70.41.3.18",
		},
		{
			name:       "untrusted peer, ignores headers even with TrustedProxies",
			remoteAddr: "8.8.8.8:54321",
			xffValue:   "203.0.113.195, 70.41.3.18",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedProxies([]netip.Prefix{trustedNet}),
				realip.WithTrustedPeers([]netip.Prefix{trustedNet}),
			},
			want: "8.8.8.8",
		},
		{
			name:       "all IPs in XFF are trusted proxies",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "10.1.0.1, 10.2.0.1, 10.3.0.1",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedProxies([]netip.Prefix{trustedNet}),
				realip.WithTrustedPeers([]netip.Prefix{trustedNet}),
			},
			want: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-For", tt.xffValue)

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestTrustedPeers(t *testing.T) {
	// Parse trusted peer networks
	privateLan, _ := netip.ParsePrefix("10.0.0.0/8")

	tests := []struct {
		name       string
		remoteAddr string
		xffValue   string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "trusted peer, uses X-Forwarded-For",
			remoteAddr: "10.0.0.1:54321",
			xffValue:   "203.0.113.195",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLan}),
			},
			want: "203.0.113.195",
		},
		{
			name:       "untrusted peer, ignores headers",
			remoteAddr: "8.8.8.8:54321",
			xffValue:   "203.0.113.195",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLan}),
			},
			want: "8.8.8.8",
		},
		{
			name:       "no trusted peers configured, ignores headers",
			remoteAddr: "8.8.8.8:54321",
			xffValue:   "203.0.113.195",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
			},
			want: "8.8.8.8",
		},
		{
			name:       "empty trusted peers, ignores headers",
			remoteAddr: "8.8.8.8:54321",
			xffValue:   "203.0.113.195",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{}),
			},
			want: "8.8.8.8",
		},
		{
			name:       "remote peer not in trusted list, ignores headers",
			remoteAddr: "172.16.0.1:54321",
			xffValue:   "203.0.113.195",
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLan}),
			},
			want: "172.16.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-For", tt.xffValue)

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestEdgeCases(t *testing.T) {
	rip := realip.New(
		realip.WithHeaders([]string{realip.XForwardedFor, realip.XRealIP, realip.TrueClientIP}),
	)

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "remote addr without port",
			remoteAddr: "192.168.1.100",
			headers:    map[string]string{},
			want:       "192.168.1.100",
		},
		{
			name:       "IPv6 address",
			remoteAddr: "[2001:db8::1]:54321",
			headers:    map[string]string{},
			want:       "2001:db8::1",
		},
		{
			name:       "X-Forwarded-For with spaces",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "  203.0.113.195  ,  70.41.3.18  "},
			want:       "70.41.3.18",
		},
		{
			name:       "empty header values",
			remoteAddr: "192.168.1.100:54321",
			headers: map[string]string{
				"X-Forwarded-For": "",
				"X-Real-IP":       "",
			},
			want: "192.168.1.100",
		},
		{
			name:       "malformed IP in header",
			remoteAddr: "192.168.1.100:54321",
			headers:    map[string]string{"X-Forwarded-For": "999.999.999.999"},
			want:       "192.168.1.100",
		},
		{
			name:       "mixed valid and invalid IPs in X-Forwarded-For",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195, invalid, 70.41.3.18"},
			want:       "70.41.3.18",
		},
		{
			name:       "only invalid IPs in X-Forwarded-For",
			remoteAddr: "192.168.1.100:54321",
			headers:    map[string]string{"X-Forwarded-For": "invalid, bad"},
			want:       "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			// Trust the peer
			if tt.remoteAddr != "" {
				addrPort, err := netip.ParseAddrPort(tt.remoteAddr)
				if err == nil {
					rip.SetTrustedPeers([]netip.Prefix{netip.PrefixFrom(addrPort.Addr(), addrPort.Addr().BitLen())})
				} else {
					// Handle cases where remoteAddr is just IP or invalid
					ipAddr, err := netip.ParseAddr(tt.remoteAddr)
					if err == nil {
						rip.SetTrustedPeers([]netip.Prefix{netip.PrefixFrom(ipAddr, ipAddr.BitLen())})
					} else {
						rip.SetTrustedPeers(nil)
					}
				}
			} else {
				rip.SetTrustedPeers(nil)
			}

			for key, value := range tt.headers {
				if value != "" {
					req.Header.Set(key, value)
				}
			}

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestHeaderPriority(t *testing.T) {
	trustedPeer, _ := netip.ParsePrefix("10.0.0.1/32")
	rip := realip.New(
		realip.WithHeaders([]string{realip.XForwardedFor, realip.XRealIP, realip.TrueClientIP}),
		realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
	)

	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name: "X-Forwarded-For has highest priority",
			headers: map[string]string{
				realip.XForwardedFor: "203.0.113.195",
				realip.XRealIP:       "198.51.100.178",
				realip.TrueClientIP:  "192.0.2.60",
			},
			want: "203.0.113.195",
		},
		{
			name: "X-Real-IP is second priority",
			headers: map[string]string{
				realip.XRealIP:      "198.51.100.178",
				realip.TrueClientIP: "192.0.2.60",
			},
			want: "198.51.100.178",
		},
		{
			name: "True-Client-IP is third priority",
			headers: map[string]string{
				realip.TrueClientIP: "192.0.2.60",
			},
			want: "192.0.2.60",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = "10.0.0.1:54321"

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestCustomHeaderOrder(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			name:    "custom header order 1",
			headers: []string{realip.TrueClientIP, realip.XRealIP, realip.XForwardedFor},
			want:    "192.0.2.60",
		},
		{
			name:    "custom header order 2",
			headers: []string{realip.XRealIP, realip.TrueClientIP, realip.XForwardedFor},
			want:    "198.51.100.178",
		},
		{
			name:    "single header",
			headers: []string{realip.XRealIP},
			want:    "198.51.100.178",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustedPeer, _ := netip.ParsePrefix("10.0.0.1/32")
			rip := realip.New(
				realip.WithHeaders(tt.headers),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer}),
			)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = "10.0.0.1:54321"
			req.Header.Set(realip.XForwardedFor, "203.0.113.195")
			req.Header.Set(realip.XRealIP, "198.51.100.178")
			req.Header.Set(realip.TrueClientIP, "192.0.2.60")

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestComplexScenarios(t *testing.T) {
	privateLAN, _ := netip.ParsePrefix("10.0.0.0/8")
	cloudflare, _ := netip.ParsePrefix("192.0.2.0/24")
	trustedPeer10, _ := netip.ParsePrefix("10.0.0.1/32")

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "trusted peer through Cloudflare",
			remoteAddr: "192.0.2.1:54321",
			headers: map[string]string{
				realip.XForwardedFor: "203.0.113.195, 192.0.2.1",
				realip.TrueClientIP:  "203.0.113.195",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.TrueClientIP, realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{cloudflare}),
			},
			want: "203.0.113.195",
		},
		{
			name:       "internal network with multiple proxies",
			remoteAddr: "10.0.0.5:54321",
			headers: map[string]string{
				realip.XForwardedFor: "203.0.113.195, 10.0.0.3, 10.0.0.4, 10.0.0.5",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedProxies([]netip.Prefix{privateLAN}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
				realip.WithProxyCnt(0),
			},
			want: "203.0.113.195",
		},
		{
			name:       "proxy chain with ProxyCnt",
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				realip.XForwardedFor: "203.0.113.195, 198.51.100.178, 192.0.2.60",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithProxyCnt(1),
				realip.WithTrustedPeers([]netip.Prefix{trustedPeer10}),
			},
			want: "198.51.100.178",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromRequestInvalidRemoteAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "malformed remote addr with header fallback",
			remoteAddr: "not-an-ip:99999",
			headers:    map[string]string{realip.XForwardedFor: "203.0.113.195"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
			},
			want: "",
		},
		{
			name:       "empty remote addr with header",
			remoteAddr: "",
			headers:    map[string]string{realip.XRealIP: "198.51.100.178"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XRealIP}),
			},
			want: "",
		},
		{
			name:       "all invalid sources",
			remoteAddr: "invalid:99999",
			headers: map[string]string{
				realip.XForwardedFor: "bad",
				realip.XRealIP:       "also-bad",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor, realip.XRealIP}),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRemoteIPExtraction(t *testing.T) {
	rip := realip.New()

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "192.168.1.1:1234",
			want:       "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[::1]:5000",
			want:       "::1",
		},
		{
			name:       "IPv6 full address with port",
			remoteAddr: "[2001:db8::1]:8080",
			want:       "2001:db8::1",
		},
		{
			name:       "IPv4 no port",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
		{
			name:       "localhost",
			remoteAddr: "127.0.0.1:3000",
			want:       "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			got := rip.FromRequest(req)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkFromRequest(b *testing.B) {
	rip := realip.New()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
	req.Header.Set("X-Real-IP", "198.51.100.178")
	req.Header.Set("True-Client-IP", "192.0.2.60")

	for b.Loop() {
		_ = rip.FromRequest(req)
	}
}

func BenchmarkFromRequest_WithTrustedPeers(b *testing.B) {
	privateLAN, _ := netip.ParsePrefix("10.0.0.0/8")

	rip := realip.New(
		realip.WithHeaders([]string{realip.XForwardedFor}),
		realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
	)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")

	for b.Loop() {
		_ = rip.FromRequest(req)
	}
}

func TestHeaderFromRequest(t *testing.T) {
	privateLAN, _ := netip.ParsePrefix("10.0.0.0/8")

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		opts       []realip.Option
		want       string
	}{
		{
			name:       "trusted peer returns X-Forwarded-For header",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195, 70.41.3.18"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "203.0.113.195, 70.41.3.18",
		},
		{
			name:       "trusted peer returns X-Real-IP header",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Real-IP": "198.51.100.178"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XRealIP}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "198.51.100.178",
		},
		{
			name:       "trusted peer with multiple headers, returns first configured",
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195",
				"X-Real-IP":       "198.51.100.178",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor, realip.XRealIP}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "203.0.113.195",
		},
		{
			name:       "trusted peer with multiple headers, respects priority order",
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.195",
				"X-Real-IP":       "198.51.100.178",
			},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XRealIP, realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "198.51.100.178",
		},
		{
			name:       "untrusted peer returns empty string",
			remoteAddr: "8.8.8.8:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "",
		},
		{
			name:       "no trusted peers configured returns empty string",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
			},
			want: "",
		},
		{
			name:       "trusted peer but no headers present returns empty string",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "",
		},
		{
			name:       "trusted peer but wrong header present returns empty string",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Real-IP": "198.51.100.178"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "",
		},
		{
			name:       "trusted peer with empty header value returns empty string",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": ""},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "",
		},
		{
			name:       "no remote address returns empty string",
			remoteAddr: "",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "",
		},
		{
			name:       "returns header with spaces preserved",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "  203.0.113.195  ,  70.41.3.18  "},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "  203.0.113.195  ,  70.41.3.18  ",
		},
		{
			name:       "returns header even with invalid IPs",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "invalid, 999.999.999.999"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
			},
			want: "invalid, 999.999.999.999",
		},
		{
			name:       "IPv6 trusted peer returns header",
			remoteAddr: "[2001:db8::1]:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.195"},
			opts: []realip.Option{
				realip.WithHeaders([]string{realip.XForwardedFor}),
				realip.WithTrustedPeers([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}),
			},
			want: "203.0.113.195",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := realip.New(tt.opts...)
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tt.remoteAddr

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			got := rip.HeaderFromRequest(req)
			if got != tt.want {
				t.Errorf("HeaderFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func BenchmarkHeaderFromRequest(b *testing.B) {
	privateLAN, _ := netip.ParsePrefix("10.0.0.0/8")

	rip := realip.New(
		realip.WithHeaders([]string{realip.XForwardedFor}),
		realip.WithTrustedPeers([]netip.Prefix{privateLAN}),
	)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")

	for b.Loop() {
		_ = rip.HeaderFromRequest(req)
	}
}
