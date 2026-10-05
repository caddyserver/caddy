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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// When ECH is rejected, the server must send its current ECH configs back so
// the client can retry with ECH instead of falling back to plaintext SNI.
func TestECHRejectionSendsRetryConfigs(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		local_certs
		admin localhost:2999
		http_port     9080
		https_port    9443
		ech ech.localhost
	}
	a.localhost {
		respond "ok"
	}
	`, "caddyfile")

	// certificates are obtained in the background; the rejected handshake
	// is completed with the public name's certificate
	waitForCertificate(t, "a.localhost")
	waitForCertificate(t, "ech.localhost")

	// a well-formed ECH config with a key the server doesn't have, like a
	// client would hold after the server's keys were rotated
	stale := echConfigList(t, "ech.localhost")

	_, err := dialECH(stale)
	var rejection *tls.ECHRejectionError
	if !errors.As(err, &rejection) {
		t.Fatalf("expected ECH to be rejected, got: %v", err)
	}
	if len(rejection.RetryConfigList) == 0 {
		t.Fatal("ECH was rejected without retry configs")
	}

	conn, err := dialECH(rejection.RetryConfigList)
	if err != nil {
		t.Fatalf("retrying with the server's retry configs: %v", err)
	}
	defer conn.Close()
	if !conn.ConnectionState().ECHAccepted {
		t.Fatal("ECH was not accepted when retrying with the server's retry configs")
	}
}

func waitForCertificate(t *testing.T, serverName string) {
	t.Helper()
	var err error
	for range 50 {
		var conn *tls.Conn
		conn, err = tls.Dial("tcp", "127.0.0.1:9443", &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec
		})
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no certificate for %s: %v", serverName, err)
}

func dialECH(configList []byte) (*tls.Conn, error) {
	return tls.Dial("tcp", "127.0.0.1:9443", &tls.Config{
		ServerName:                     "a.localhost",
		InsecureSkipVerify:             true, //nolint:gosec
		EncryptedClientHelloConfigList: configList,
		// the outer handshake uses the public name's certificate from the
		// test's internal CA, which this client doesn't trust
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	})
}

// echConfigList returns an ECHConfigList holding one version 0xfe0d config
// with a fresh X25519 key, HKDF-SHA256 and AES-128-GCM.
func echConfigList(t *testing.T, publicName string) []byte {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()

	var contents []byte
	contents = append(contents, 1)                             // config_id
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // KEM: DHKEM(X25519, HKDF-SHA256)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	contents = binary.BigEndian.AppendUint16(contents, 4)      // cipher suites length
	contents = binary.BigEndian.AppendUint16(contents, 0x0001) // KDF: HKDF-SHA256
	contents = binary.BigEndian.AppendUint16(contents, 0x0001) // AEAD: AES-128-GCM
	contents = append(contents, 0)                             // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions

	config := binary.BigEndian.AppendUint16(nil, 0xfe0d) // version
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	return append(binary.BigEndian.AppendUint16(nil, uint16(len(config))), config...)
}
