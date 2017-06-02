package caddytls

import "github.com/xenolf/lego/acme"

// own ChallengeProvider type to be used in Caddy plugins over acme.ChallengeProvider directly, to avoid
// https://github.com/mattfarina/golang-broken-vendor
type ChallengeProvider acme.ChallengeProvider