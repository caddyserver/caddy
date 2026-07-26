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

package integration

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestRFC9440HeaderSafetyIntegration(t *testing.T) {
	tester := caddytest.NewTester(t)
	bt := "`"
	caddyfileConfig := " {\n" +
		"\tskip_install_trust\n" +
		"\tadmin localhost:2999\n" +
		"\thttp_port 9080\n" +
		"\thttps_port 9443\n" +
		"\tgrace_period 1ns\n" +
		"}\n" +
		"localhost:9080 {\n" +
		"\theader -Client-Cert\n" +
		"\theader -Client-Cert-Chain\n" +
		"\t@has_mtls expression " + bt + "{http.request.tls.client.certificate_rfc9440} != \"\"" + bt + "\n" +
		"\theader @has_mtls Client-Cert {http.request.tls.client.certificate_rfc9440}\n" +
		"\theader @has_mtls Client-Cert-Chain {http.request.tls.client.certificate_chain_rfc9440}\n" +
		"\trespond \"ok\" 200\n" +
		"}\n"
	tester.InitServer(caddyfileConfig, "caddyfile")

	// Send a request with spoofed Client-Cert / Client-Cert-Chain headers
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Client-Cert", "spoofed-by-client")
	req.Header.Set("Client-Cert-Chain", "spoofed-chain")

	resp := tester.AssertResponseCode(req, 200)

	// Both headers must be completely absent on a non-mTLS request
	if vals, present := resp.Header["Client-Cert"]; present {
		t.Errorf("Client-Cert should be absent on plain HTTP request, but got: %v", vals)
	}
	if vals, present := resp.Header["Client-Cert-Chain"]; present {
		t.Errorf("Client-Cert-Chain should be absent on plain HTTP request, but got: %v", vals)
	}
}
