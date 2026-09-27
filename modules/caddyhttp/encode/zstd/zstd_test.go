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

package caddyzstd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

const dictPath = "testdata/sample.dict"

var payload = []byte(`{"status":"ok","user":{"id":42,"name":"user42","role":"admin","tags":["a","b"]},"ts":"2026-09-27T00:00:02Z"}`)

func encodeWith(t *testing.T, z Zstd) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := z.NewEncoder()
	enc.Reset(&buf)
	if _, err := enc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func TestDictionaryRoundTrip(t *testing.T) {
	z := Zstd{Dictionary: dictPath}
	if err := z.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	out := encodeWith(t, z)

	dict, err := os.ReadFile(dictPath)
	if err != nil {
		t.Fatalf("read dictionary: %v", err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderDicts(dict))
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer dec.Close()

	got, err := dec.DecodeAll(out, nil)
	if err != nil {
		t.Fatalf("decode with dictionary: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip mismatch:\ngot  %s\nwant %s", got, payload)
	}

	// Decoding alone does not prove the dictionary was used, since a decoder
	// holding dictionaries also reads plain frames. Check the frame refers to it.
	var hdr zstd.Header
	if err := hdr.Decode(out); err != nil {
		t.Fatalf("decode frame header: %v", err)
	}
	if hdr.DictionaryID == 0 {
		t.Error("frame carries no dictionary ID, so the dictionary was not applied")
	}
}

// A dictionary is not carried in the frame, so a decoder without it must fail
// rather than silently produce different bytes.
func TestDictionaryNotDecodableWithoutIt(t *testing.T) {
	z := Zstd{Dictionary: dictPath}
	if err := z.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	out := encodeWith(t, z)

	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer dec.Close()

	if _, err := dec.DecodeAll(out, nil); err == nil {
		t.Error("expected an error decoding a dictionary frame without the dictionary")
	}
}

func TestWithoutDictionaryStillDecodesPlain(t *testing.T) {
	var z Zstd
	if err := z.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	out := encodeWith(t, z)

	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer dec.Close()

	got, err := dec.DecodeAll(out, nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip mismatch:\ngot  %s\nwant %s", got, payload)
	}
}

func TestProvisionRejectsBadDictionary(t *testing.T) {
	for name, path := range map[string]string{
		"missing file": filepath.Join("testdata", "does-not-exist.dict"),
		"not trained":  filepath.Join("testdata", "invalid.dict"),
	} {
		t.Run(name, func(t *testing.T) {
			z := Zstd{Dictionary: path}
			if err := z.Provision(caddy.Context{}); err == nil {
				t.Fatal("expected provision to fail")
			}
		})
	}
}

func TestUnmarshalCaddyfileDictionary(t *testing.T) {
	for name, tc := range map[string]struct {
		input   string
		want    string
		wantErr bool
	}{
		"dictionary": {
			input: `zstd {
				dictionary testdata/sample.dict
			}`,
			want: "testdata/sample.dict",
		},
		"with level": {
			input: `zstd {
				level best
				dictionary testdata/sample.dict
			}`,
			want: "testdata/sample.dict",
		},
		"no argument": {
			input: `zstd {
				dictionary
			}`,
			wantErr: true,
		},
		"repeated": {
			input: `zstd {
				dictionary a.dict
				dictionary b.dict
			}`,
			wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var z Zstd
			err := z.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if z.Dictionary != tc.want {
				t.Errorf("Dictionary = %q, want %q", z.Dictionary, tc.want)
			}
		})
	}
}

func TestDictionaryImprovesRatioOnSmallPayloads(t *testing.T) {
	var plain Zstd
	if err := plain.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	withDict := Zstd{Dictionary: dictPath}
	if err := withDict.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	plainLen := len(encodeWith(t, plain))
	dictLen := len(encodeWith(t, withDict))
	if dictLen >= plainLen {
		t.Errorf("expected the dictionary to compress better: plain=%d dict=%d", plainLen, dictLen)
	}
}

func TestProvisionErrorMentionsTraining(t *testing.T) {
	z := Zstd{Dictionary: filepath.Join("testdata", "invalid.dict")}
	err := z.Provision(caddy.Context{})
	if err == nil {
		t.Fatal("expected provision to fail")
	}
	if !strings.Contains(err.Error(), "zstd --train") {
		t.Errorf("error should point at how to build a dictionary, got: %v", err)
	}
}
