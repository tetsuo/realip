package realip

import "net/netip"

// Option is a function that configures RealIP settings.
type Option func(r *RealIP)

// WithHeaders sets which HTTP headers to check for the real client IP.
// Common headers include X-Forwarded-For, X-Real-IP, and True-Client-IP.
// The headers are checked in order; the first matching header is used.
func WithHeaders(headers []string) Option {
	return func(r *RealIP) {
		r.headers = headers
	}
}

// WithTrustedProxies sets the IP ranges of internal proxies in a chain.
// When you have multiple proxies, this helps identify which IPs in the X-Forwarded-For
// header are proxies so they can be skipped to find the real client IP.
func WithTrustedProxies(proxies []netip.Prefix) Option {
	return func(r *RealIP) {
		r.trustedProxies = proxies
	}
}

// WithTrustedPeers sets the IP ranges that are allowed to set client IP headers.
// This is a security-critical setting. Only requests from trusted peers (proxies)
// will have their headers checked. Other requests will use the remote address.
func WithTrustedPeers(peers []netip.Prefix) Option {
	return func(r *RealIP) {
		r.trustedPeers = peers
	}
}

// WithProxyCnt sets the exact number of proxies in the chain.
// If you know there are exactly N proxies between the client and your server,
// use this to skip those N IPs from the X-Forwarded-For header and get the real client IP.
func WithProxyCnt(cnt int) Option {
	return func(r *RealIP) {
		r.proxyCnt = cnt
	}
}

// SetHeaders updates the headers to check for the real client IP.
// This allows changing configuration after RealIP has been created.
func (r *RealIP) SetHeaders(headers []string) {
	r.headers = headers
}

// SetTrustedProxies updates the IP ranges of internal proxies.
// This allows changing configuration after RealIP has been created.
func (r *RealIP) SetTrustedProxies(proxies []netip.Prefix) {
	r.trustedProxies = proxies
}

// SetTrustedPeers updates the IP ranges that are allowed to set client IP headers.
// This allows changing configuration after RealIP has been created.
func (r *RealIP) SetTrustedPeers(peers []netip.Prefix) {
	r.trustedPeers = peers
}

// SetProxyCnt updates the exact number of proxies in the chain.
// This allows changing configuration after RealIP has been created.
func (r *RealIP) SetProxyCnt(cnt int) {
	r.proxyCnt = cnt
}
