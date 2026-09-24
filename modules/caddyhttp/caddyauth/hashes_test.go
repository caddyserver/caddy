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

package caddyauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func init() {
	caddy.RegisterModule(testHash{})
	caddy.RegisterModule(testCompareOnlyHash{})
}

// testHash is a third-party-style hash module used to
// test that modules in the http.authentication.hashes
// namespace can be used by name.
type testHash struct {
	provisioned bool
}

func (testHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.hashes.testhash",
		New: func() caddy.Module { return new(testHash) },
	}
}

func (th *testHash) Provision(caddy.Context) error {
	th.provisioned = true
	return nil
}

func (testHash) Compare(hashed, plaintext []byte) (bool, error) {
	return bytes.Equal(hashed, append([]byte("testhash:"), plaintext...)), nil
}

func (th testHash) Hash(plaintext []byte) ([]byte, error) {
	if !th.provisioned {
		return nil, errors.New("testhash: not provisioned")
	}
	return append([]byte("testhash:"), plaintext...), nil
}

func (testHash) FakeHash() []byte { return []byte("testhash:fake") }

// testCompareOnlyHash can compare, but not generate, hashes.
type testCompareOnlyHash struct{}

func (testCompareOnlyHash) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.hashes.testcompareonly",
		New: func() caddy.Module { return new(testCompareOnlyHash) },
	}
}

func (testCompareOnlyHash) Compare(hashed, plaintext []byte) (bool, error) {
	return bytes.Equal(hashed, plaintext), nil
}

func adaptBasicAuth(t *testing.T, input string) (string, error) {
	t.Helper()
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	result, _, err := adapter.Adapt([]byte(input), map[string]any{"filename": "Caddyfile"})
	if err != nil {
		return "", err
	}

	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []struct {
							Providers struct {
								HTTPBasic struct {
									Hash struct {
										Algorithm string `json:"algorithm"`
									} `json:"hash"`
								} `json:"http_basic"`
							} `json:"providers"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(result, &cfg); err != nil {
		t.Fatalf("unmarshaling adapted config: %v\n%s", err, result)
	}
	srv, ok := cfg.Apps.HTTP.Servers["srv0"]
	if !ok || len(srv.Routes) != 1 || len(srv.Routes[0].Handle) != 1 {
		t.Fatalf("unexpected adapted config: %s", result)
	}
	return srv.Routes[0].Handle[0].Providers.HTTPBasic.Hash.Algorithm, nil
}

func TestBasicAuthCaddyfileHashModules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		expected  string
	}{
		{name: "default", algorithm: "", expected: "bcrypt"},
		{name: "bcrypt", algorithm: "bcrypt", expected: "bcrypt"},
		{name: "argon2id", algorithm: "argon2id", expected: "argon2id"},
		{name: "third-party", algorithm: "testhash", expected: "testhash"},
		{name: "third-party compare only", algorithm: "testcompareonly", expected: "testcompareonly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := ":80 {\n\tbasic_auth " + tc.algorithm + " {\n\t\talice dGVzdGhhc2g6c2VjcmV0\n\t}\n}\n"
			algorithm, err := adaptBasicAuth(t, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if algorithm != tc.expected {
				t.Errorf("expected hash algorithm %q, got %q", tc.expected, algorithm)
			}
		})
	}
}

func TestBasicAuthCaddyfileUnknownHash(t *testing.T) {
	_, err := adaptBasicAuth(t, ":80 {\n\tbasic_auth nope {\n\t\talice c2VjcmV0\n\t}\n}\n")
	if err == nil {
		t.Fatal("expected an error for an unknown hash algorithm, got nil")
	}
	for _, want := range []string{"unrecognized hash algorithm: nope", "argon2id", "bcrypt", "testhash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to contain %q, got: %v", want, err)
		}
	}
}

func TestBasicAuthProvisionHashModule(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	hba := HTTPBasicAuth{
		HashRaw: json.RawMessage(`{"algorithm": "testhash"}`),
		AccountList: []Account{{
			Username: "alice",
			Password: "dGVzdGhhc2g6c2VjcmV0", // base64("testhash:secret")
		}},
		HashCache: new(Cache),
	}
	if err := hba.Provision(ctx); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if _, ok := hba.Hash.(*testHash); !ok {
		t.Fatalf("expected hash module to be *testHash, got %T", hba.Hash)
	}
	if string(hba.fakePassword) != "testhash:fake" {
		t.Errorf("expected fake password from module, got %q", hba.fakePassword)
	}
	if ok, err := hba.correctPassword(hba.Accounts["alice"], []byte("secret")); err != nil || !ok {
		t.Errorf("expected password to match (err=%v)", err)
	}
	if ok, err := hba.correctPassword(hba.Accounts["alice"], []byte("wrong")); err != nil || ok {
		t.Errorf("expected password not to match (err=%v)", err)
	}
}

func runHashPassword(t *testing.T, algorithm, plaintext string) (string, error) {
	t.Helper()

	fs := pflag.NewFlagSet("hash-password", pflag.ContinueOnError)
	fs.String("plaintext", plaintext, "")
	fs.String("algorithm", algorithm, "")
	fs.Int("bcrypt-cost", defaultBcryptCost, "")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	_, cmdErr := cmdHashPassword(caddycmd.Flags{FlagSet: fs})
	os.Stdout = stdout
	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out)), cmdErr
}

func TestHashPasswordCommandHashModule(t *testing.T) {
	out, err := runHashPassword(t, "testhash", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "testhash:secret" {
		t.Errorf("expected output %q, got %q", "testhash:secret", out)
	}
}

func TestHashPasswordCommandErrors(t *testing.T) {
	_, err := runHashPassword(t, "nope", "secret")
	if err == nil {
		t.Fatal("expected an error for an unknown hash algorithm, got nil")
	}
	for _, want := range []string{"unrecognized hash algorithm: nope", "argon2id", "bcrypt", "testhash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to contain %q, got: %v", want, err)
		}
	}

	_, err = runHashPassword(t, "testcompareonly", "secret")
	if err == nil || !strings.Contains(err.Error(), "does not support generating hashes") {
		t.Errorf("expected an error for a hash module that cannot hash, got: %v", err)
	}
}
