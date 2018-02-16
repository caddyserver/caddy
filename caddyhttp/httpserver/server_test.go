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

package httpserver

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestAddress(t *testing.T) {
	addr := "127.0.0.1:9005"
	srv := &Server{Server: &http.Server{Addr: addr}}

	if got, want := srv.Address(), addr; got != want {
		t.Errorf("Expected '%s' but got '%s'", want, got)
	}
}

func TestMakeHTTPServerWithTimeouts(t *testing.T) {
	for i, tc := range []struct {
		group    []*SiteConfig
		expected Timeouts
	}{
		{
			group: []*SiteConfig{{Timeouts: Timeouts{}}},
			expected: Timeouts{
				ReadTimeout:       defaultTimeouts.ReadTimeout,
				ReadHeaderTimeout: defaultTimeouts.ReadHeaderTimeout,
				WriteTimeout:      defaultTimeouts.WriteTimeout,
				IdleTimeout:       defaultTimeouts.IdleTimeout,
			},
		},
		{
			group: []*SiteConfig{{Timeouts: Timeouts{
				ReadTimeout:          1 * time.Second,
				ReadTimeoutSet:       true,
				ReadHeaderTimeout:    2 * time.Second,
				ReadHeaderTimeoutSet: true,
			}}},
			expected: Timeouts{
				ReadTimeout:       1 * time.Second,
				ReadHeaderTimeout: 2 * time.Second,
				WriteTimeout:      defaultTimeouts.WriteTimeout,
				IdleTimeout:       defaultTimeouts.IdleTimeout,
			},
		},
		{
			group: []*SiteConfig{{Timeouts: Timeouts{
				ReadTimeoutSet:  true,
				WriteTimeoutSet: true,
			}}},
			expected: Timeouts{
				ReadTimeout:       0,
				ReadHeaderTimeout: defaultTimeouts.ReadHeaderTimeout,
				WriteTimeout:      0,
				IdleTimeout:       defaultTimeouts.IdleTimeout,
			},
		},
		{
			group: []*SiteConfig{
				{Timeouts: Timeouts{
					ReadTimeout:     2 * time.Second,
					ReadTimeoutSet:  true,
					WriteTimeout:    2 * time.Second,
					WriteTimeoutSet: true,
				}},
				{Timeouts: Timeouts{
					ReadTimeout:     1 * time.Second,
					ReadTimeoutSet:  true,
					WriteTimeout:    1 * time.Second,
					WriteTimeoutSet: true,
				}},
			},
			expected: Timeouts{
				ReadTimeout:       1 * time.Second,
				ReadHeaderTimeout: defaultTimeouts.ReadHeaderTimeout,
				WriteTimeout:      1 * time.Second,
				IdleTimeout:       defaultTimeouts.IdleTimeout,
			},
		},
		{
			group: []*SiteConfig{{Timeouts: Timeouts{
				ReadHeaderTimeout:    5 * time.Second,
				ReadHeaderTimeoutSet: true,
				IdleTimeout:          10 * time.Second,
				IdleTimeoutSet:       true,
			}}},
			expected: Timeouts{
				ReadTimeout:       defaultTimeouts.ReadTimeout,
				ReadHeaderTimeout: 5 * time.Second,
				WriteTimeout:      defaultTimeouts.WriteTimeout,
				IdleTimeout:       10 * time.Second,
			},
		},
	} {
		actual := makeHTTPServerWithTimeouts("127.0.0.1:9005", tc.group)

		if got, want := actual.Addr, "127.0.0.1:9005"; got != want {
			t.Errorf("Test %d: Expected Addr=%s, but was %s", i, want, got)
		}
		if got, want := actual.ReadTimeout, tc.expected.ReadTimeout; got != want {
			t.Errorf("Test %d: Expected ReadTimeout=%v, but was %v", i, want, got)
		}
		if got, want := actual.ReadHeaderTimeout, tc.expected.ReadHeaderTimeout; got != want {
			t.Errorf("Test %d: Expected ReadHeaderTimeout=%v, but was %v", i, want, got)
		}
		if got, want := actual.WriteTimeout, tc.expected.WriteTimeout; got != want {
			t.Errorf("Test %d: Expected WriteTimeout=%v, but was %v", i, want, got)
		}
		if got, want := actual.IdleTimeout, tc.expected.IdleTimeout; got != want {
			t.Errorf("Test %d: Expected IdleTimeout=%v, but was %v", i, want, got)
		}
	}
}

func TestTrimPathPrefix(t *testing.T) {
	for i, pt := range []struct {
		path       string
		prefix     string
		expected   string
		shouldFail bool
	}{
		{
			path:       "/my/path",
			prefix:     "/my",
			expected:   "/path",
			shouldFail: false,
		},
		{
			path:       "/my/%2f/path",
			prefix:     "/my",
			expected:   "/%2f/path",
			shouldFail: false,
		},
		{
			path:       "/my/path",
			prefix:     "/my/",
			expected:   "/path",
			shouldFail: false,
		},
		{
			path:       "/my///path",
			prefix:     "/my",
			expected:   "/path",
			shouldFail: true,
		},
		{
			path:       "/my///path",
			prefix:     "/my",
			expected:   "///path",
			shouldFail: false,
		},
		{
			path:       "/my/path///slash",
			prefix:     "/my",
			expected:   "/path///slash",
			shouldFail: false,
		},
		{
			path:       "/my/%2f/path/%2f",
			prefix:     "/my",
			expected:   "/%2f/path/%2f",
			shouldFail: false,
		}, {
			path:       "/my/%20/path",
			prefix:     "/my",
			expected:   "/%20/path",
			shouldFail: false,
		}, {
			path:       "/path",
			prefix:     "",
			expected:   "/path",
			shouldFail: false,
		}, {
			path:       "/path/my/",
			prefix:     "/my",
			expected:   "/path/my/",
			shouldFail: false,
		}, {
			path:       "",
			prefix:     "/my",
			expected:   "/",
			shouldFail: false,
		}, {
			path:       "/apath",
			prefix:     "",
			expected:   "/apath",
			shouldFail: false,
		},
	} {

		u, _ := url.Parse(pt.path)
		if got, want := trimPathPrefix(u, pt.prefix), pt.expected; got.EscapedPath() != want {
			if !pt.shouldFail {

				t.Errorf("Test %d: Expected='%s', but was '%s' ", i, want, got.EscapedPath())
			}
		} else if pt.shouldFail {
			t.Errorf("SHOULDFAIL Test %d: Expected='%s', and was '%s' but should fail", i, want, got.EscapedPath())
		}
	}
}

func TestMakeHTTPServerWithHeaderLimit(t *testing.T) {
	for name, c := range map[string]struct {
		group  []*SiteConfig
		expect int
	}{
		"disable": {
			group:  []*SiteConfig{{}},
			expect: 0,
		},
		"oneSite": {
			group: []*SiteConfig{{Limits: Limits{
				MaxRequestHeaderSize: 100,
			}}},
			expect: 100,
		},
		"multiSites": {
			group: []*SiteConfig{
				{Limits: Limits{MaxRequestHeaderSize: 100}},
				{Limits: Limits{MaxRequestHeaderSize: 50}},
			},
			expect: 50,
		},
	} {
		c := c
		t.Run(name, func(t *testing.T) {
			actual := makeHTTPServerWithHeaderLimit(&http.Server{}, c.group)
			if got := actual.MaxHeaderBytes; got != c.expect {
				t.Errorf("Expect %d, but got %d", c.expect, got)
			}
		})
	}
}
