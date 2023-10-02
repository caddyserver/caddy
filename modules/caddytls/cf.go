//go:build cfgo

package caddytls

// This file adds support for X25519Kyber768Draft00, a post-quantum
// key agreement that is currently being rolled out by Chrome [1]
// and Cloudflare [2,3]. For more context, see the PR [4].
//
// [1] https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html
// [2] https://blog.cloudflare.com/post-quantum-for-all/
// [3] https://blog.cloudflare.com/post-quantum-to-origins/
// [4] https://github.com/caddyserver/caddy/pull/5852

import (
	"crypto/tls"
)

func init() {
	SupportedCurves["X25519Kyber768Draft00"] = tls.X25519Kyber768Draft00
	defaultCurves = append(
		[]tls.CurveID{tls.X25519Kyber768Draft00},
		defaultCurves...,
	)
}
