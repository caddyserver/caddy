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

package caddyhttp

import (
	"crypto/tls"
	"testing"
)

// BenchmarkBuildHTTP3Server_WebTransportOff measures the cost of
// constructing the HTTP/3 server for a deployment that does NOT opt in
// to WebTransport. This is the primary cost comparison steadytao asked
// about: any non-zero delta vs. pre-WebTransport Caddy would need to be
// justified, and the implementation is structured so the delta is
// exactly the branch check on EnableWebTransport.
//
// This benchmark does not exercise the per-stream dispatch cost
// (which is inside webtransport-go / quic-go and would require a full
// QUIC setup to measure in isolation). The meaningful regression guard
// is whether buildHTTP3Server with the flag off does the same work
// as on pre-PR master.
func BenchmarkBuildHTTP3Server_WebTransportOff(b *testing.B) {
	s := &Server{}
	tlsCfg := &tls.Config{}
	b.ResetTimer()
	for b.Loop() {
		_ = s.buildHTTP3Server(tlsCfg)
	}
}

// BenchmarkBuildHTTP3Server_WebTransportOn measures the same
// construction with WebTransport enabled. The cost difference vs. the
// Off variant is the one-time setup webtransport.ConfigureHTTP3Server
// performs (AdditionalSettings, ConnContext, EnableDatagrams, etc.)
// plus setting EnableStreamResetPartialDelivery on the QUIC config.
func BenchmarkBuildHTTP3Server_WebTransportOn(b *testing.B) {
	s := &Server{EnableWebTransport: true}
	tlsCfg := &tls.Config{}
	b.ResetTimer()
	for b.Loop() {
		_ = s.buildHTTP3Server(tlsCfg)
	}
}
