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

package fastcgi

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestWritePairsOversized(t *testing.T) {
	tooLong := strings.Repeat("N", maxWrite-7)
	muchTooLong := strings.Repeat("N", maxWrite+1)
	longestName := strings.Repeat("N", maxWrite-8)

	tests := []struct {
		name  string
		pairs map[string]string
		want  map[string]string
	}{
		{
			name:  "name too long to fit is skipped",
			pairs: map[string]string{"SCRIPT_NAME": "/index.php", tooLong: "x", muchTooLong: "x"},
			want:  map[string]string{"SCRIPT_NAME": "/index.php"},
		},
		{
			name:  "longest name that fits is kept with an empty value",
			pairs: map[string]string{longestName: "x"},
			want:  map[string]string{longestName: ""},
		},
		{
			name:  "long value is truncated",
			pairs: map[string]string{"K": strings.Repeat("v", maxWrite)},
			want:  map[string]string{"K": strings.Repeat("v", maxWrite-9)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer serverConn.Close()

			errCh := make(chan error, 1)
			go func() {
				defer clientConn.Close()
				w := &streamWriter{c: &client{rwc: clientConn, reqID: 1}, buf: new(bytes.Buffer), recType: Params}
				errCh <- w.writePairs(tt.pairs)
			}()

			data, err := io.ReadAll(serverConn)
			if err != nil {
				t.Fatalf("reading params: %v", err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("writePairs: %v", err)
			}

			got := decodeParams(t, data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %d params, want %d", len(got), len(tt.want))
				for k, v := range got {
					if tt.want[k] != v {
						t.Errorf("param with %d-byte name has %d-byte value, want %d bytes", len(k), len(v), len(tt.want[k]))
					}
				}
			}
		})
	}
}

// decodeParams reads the name-value pairs out of a stream of Params records.
func decodeParams(t *testing.T, data []byte) map[string]string {
	t.Helper()

	var stream []byte
	for len(data) > 0 {
		if len(data) < 8 {
			t.Fatalf("short record header: %d bytes", len(data))
		}
		if data[1] != Params {
			t.Fatalf("record type %d, want %d", data[1], Params)
		}
		contentLen := int(binary.BigEndian.Uint16(data[4:6]))
		end := 8 + contentLen + int(data[6])
		if len(data) < end {
			t.Fatalf("short record: %d bytes, want %d", len(data), end)
		}
		stream = append(stream, data[8:8+contentLen]...)
		data = data[end:]
	}

	pairs := make(map[string]string)
	for len(stream) > 0 {
		var nameLen, valueLen int
		nameLen, stream = decodeSize(t, stream)
		valueLen, stream = decodeSize(t, stream)
		if len(stream) < nameLen+valueLen {
			t.Fatalf("short pair: %d bytes, want %d", len(stream), nameLen+valueLen)
		}
		pairs[string(stream[:nameLen])] = string(stream[nameLen : nameLen+valueLen])
		stream = stream[nameLen+valueLen:]
	}
	return pairs
}

func decodeSize(t *testing.T, b []byte) (int, []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("missing pair length")
	}
	if b[0]>>7 == 0 {
		return int(b[0]), b[1:]
	}
	if len(b) < 4 {
		t.Fatalf("short pair length: %d bytes", len(b))
	}
	return int(binary.BigEndian.Uint32(b) &^ (1 << 31)), b[4:]
}
