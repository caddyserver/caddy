package httpserver

import (
	"net/http"
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

func TestMakeHTTPServer(t *testing.T) {
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
