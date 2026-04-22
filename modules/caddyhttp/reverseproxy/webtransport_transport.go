// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// dialUpstreamWebTransport opens a WebTransport session to the upstream at
// urlStr (an https URL), forwarding reqHdr as headers on the Extended
// CONNECT request. The returned session is owned by the caller and must be
// closed when no longer in use. Return-value order matches
// webtransport.Dialer.Dial: (response, session, error).
//
// EXPERIMENTAL: this helper is an internal building block for the upcoming
// WebTransport reverse-proxy transport. Shape and behavior may change.
func dialUpstreamWebTransport(ctx context.Context, tlsCfg *tls.Config, urlStr string, reqHdr http.Header) (*http.Response, *webtransport.Session, error) {
	d := &webtransport.Dialer{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	return d.Dial(ctx, urlStr, reqHdr)
}
