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
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStderrIsBounded(t *testing.T) {
	const chunk = 32 << 10
	const chunks = 3 * maxStderr / chunk
	records := []fcgiRecord{stdout("Content-Type: text/plain\r\n\r\nhi")}
	for range chunks {
		records = append(records, fcgiRecord{recType: Stderr, content: strings.Repeat("E", chunk)})
	}
	records = append(records, stdout(""))

	t.Run("captured", func(t *testing.T) {
		addr, closed := fcgiResponder(t, sendRecords(records...))
		resp, logs := fcgiRequest(t, addr, "GET", 0)
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "hi" {
			t.Fatalf("body %q, err %v", body, err)
		}
		resp.Body.Close()
		waitClosed(t, closed)

		entries := logs.FilterMessage("stderr").All()
		if len(entries) != 1 {
			t.Fatalf("got %d stderr log entries, want 1", len(entries))
		}
		fields := entries[0].ContextMap()
		if n := len(fields["body"].(string)); n != maxStderr {
			t.Errorf("logged %d stderr bytes, want %d", n, maxStderr)
		}
		if n := fields["dropped_bytes"]; n != int64(chunks*chunk-maxStderr) {
			t.Errorf("dropped_bytes = %v, want %d", n, chunks*chunk-maxStderr)
		}
	})

	t.Run("not captured", func(t *testing.T) {
		addr, closed := fcgiResponder(t, sendRecords(records...))
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		c := &client{rwc: conn, reqID: 1}
		resp, err := c.Request(map[string]string{"REQUEST_METHOD": "GET", "CONTENT_LENGTH": "0"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "hi" {
			t.Fatalf("body %q, err %v", body, err)
		}
		if n := resp.Body.(clientCloser).r.stderr.Len(); n != 0 {
			t.Errorf("kept %d stderr bytes with capture disabled, want 0", n)
		}
		resp.Body.Close()
		waitClosed(t, closed)
	})
}
