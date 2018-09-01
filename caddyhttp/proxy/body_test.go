// Copyright 2015 Light Code Labs, LLC
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

package proxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyRetry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
		r.Body.Close()
	}))
	defer ts.Close()

	testcase := "test content"
	req, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewBufferString(testcase))
	if err != nil {
		t.Fatal(err)
	}

	body, err := newBufferedBody(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Body = body
	}

	// simulate fail request
	host := req.URL.Host
	req.URL.Host = "example.com"
	body.rewind()
	_, _ = http.DefaultTransport.RoundTrip(req)

	// retry request
	req.URL.Host = host
	body.rewind()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if string(result) != testcase {
		t.Fatalf("result = %s, want %s", result, testcase)
	}

	// try one more time for body reuse
	body.rewind()
	resp, err = http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	result, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if string(result) != testcase {
		t.Fatalf("result = %s, want %s", result, testcase)
	}
}
