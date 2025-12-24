// Package realip provides functions determine the client IP address by inspecting
// HTTP request headers behind a proxy.
package realip

import (
	"net/http"
	"net/netip"
	"strings"
)

// Common HTTP request headers.
const (
	XRealIP       = "X-Real-IP"
	XForwardedFor = "X-Forwarded-For"
	TrueClientIP  = "True-Client-IP"
)

var noIP = netip.Addr{}

// RealIP holds settings for extracting the client IP from an HTTP request.
type RealIP struct {
	headers        []string
	trustedProxies []netip.Prefix
	trustedPeers   []netip.Prefix
	proxyCnt       int
}

// New creates a RealIP with the given options.
func New(opts ...Option) *RealIP {
	r := &RealIP{}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// FromRequest gets the client IP from the request.
func (r *RealIP) FromRequest(req *http.Request) string {
	// Get the direct peer IP first.
	peerIP := getPeerAddr(req)
	if peerIP == noIP {
		return ""
	}

	// If there aren't any trusted peers configured, assume the server is facing the public internet directly.
	// Ignoring headers is the only secure default.
	if len(r.trustedPeers) == 0 {
		return peerIP.String()
	}

	// Verify if the immediate peer is trusted to send headers.
	if !ipInNets(peerIP, r.trustedPeers) {
		// The request came from an untrusted source (e.g., directly from a user
		// bypassing the load balancer). Ignore headers, use the peer IP.
		return peerIP.String()
	}

	// The peer is trusted; try to resolve the client IP from headers.
	if resolvedIP := r.ipFromHeaders(req); resolvedIP != noIP {
		return resolvedIP.String()
	}

	// Fallback: even if headers failed, the peer IP is valid.
	return peerIP.String()
}

func (r *RealIP) ipFromHeaders(req *http.Request) netip.Addr {
	for _, header := range r.headers {
		headerValue := req.Header.Get(header)
		if headerValue == "" {
			continue
		}

		ips := strings.Split(headerValue, ",")

		// Handle X-Forwarded-For specific logic
		if header == XForwardedFor {
			// If a proxy count is configured, skip the last N hops blindly
			// (e.g., Cloudflare + Nginx setup where you trust the last 2 hops implicitly)
			startIdx := len(ips) - 1 - r.proxyCnt
			if startIdx < 0 {
				continue
			}

			// Walk backwards from the calculated start index
			return ipFromXForwardedFor(r.trustedProxies, ips, startIdx)
		}

		// For single-value headers like X-Real-IP or True-Client-IP
		// Take the last value if multiple are present (rare but possible)
		h := strings.TrimSpace(ips[len(ips)-1])
		ip, err := netip.ParseAddr(h)
		if err == nil {
			return ip
		}
	}
	return noIP
}

func ipFromXForwardedFor(trustedProxies []netip.Prefix, ips []string, idx int) netip.Addr {
	// Walk backwards looking for the first IP that is NOT in the trusted proxies list.
	// That IP is the real client.
	for i := idx; i >= 0; i-- {
		h := strings.TrimSpace(ips[i])
		ip, err := netip.ParseAddr(h)
		if err != nil {
			continue
		}

		// If the IP is trusted, keep walking backwards.
		if ipInNets(ip, trustedProxies) {
			continue
		}

		// Found a non-trusted IP; this is the client.
		return ip
	}

	// If the walk reaches the beginning and everything was trusted,
	// the last IP checked (the furthest one) is the best guess.
	// However, usually, the last valid parsed IP would be returned.
	return noIP
}

func getPeerAddr(req *http.Request) netip.Addr {
	// Note that netip.ParseAddrPort is more strict and zero-alloc compared to net.SplitHostPort
	addrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err == nil {
		return addrPort.Addr()
	}

	// Fallback for cases where RemoteAddr might just be an IP
	ip, err := netip.ParseAddr(req.RemoteAddr)
	if err == nil {
		return ip
	}

	return noIP
}

func ipInNets(ip netip.Addr, nets []netip.Prefix) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
