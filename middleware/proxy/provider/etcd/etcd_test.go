package etcd

import (
	"fmt"
	"testing"

	"github.com/mholt/caddy/middleware/proxy/provider"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		address  string
		expected *Provider
	}{
		{
			"etcd://localhost:2015/",
			&Provider{
				endpoints: []string{"http://localhost:2015"},
				directory: "",
			},
		},
		{
			"etcdlocalhost:2015", nil,
		},
		{
			"user:pass@localhost:2015", nil,
		},
		{
			"etcd://user:pass@localhost:2015",
			&Provider{
				endpoints: []string{"http://localhost:2015"},
				username:  "user",
				password:  "pass",
			},
		},
		{
			"etcd://localhost:2015,localhost:2016",
			&Provider{
				endpoints: []string{"http://localhost:2015", "http://localhost:2016"},
			},
		},
		{
			"etcd://user:pass@localhost:2015,localhost:2016",
			&Provider{
				endpoints: []string{"http://localhost:2015", "http://localhost:2016"},
				username:  "user",
				password:  "pass",
			},
		},
		{
			"etcd://user:pass@localhost:2015/directory",
			&Provider{
				endpoints: []string{"http://localhost:2015"},
				username:  "user",
				password:  "pass",
				directory: "/directory",
			},
		},
		{
			"etcd://user:pass@2015/directory",
			&Provider{
				endpoints: []string{"http://2015"},
				username:  "user",
				password:  "pass",
				directory: "/directory",
			},
		},
	}

	for i, test := range tests {
		pr, _ := parseAddr(test.address)
		if !equalProvider(test.expected, pr, t) {
			t.Errorf("Test %d: failed", i)
		}
	}

}

func equalProvider(expected, value *Provider, t *testing.T) bool {
	if expected == nil && value != nil {
		return false
	} else if expected == nil {
		return true
	}

	if expected.directory == "" {
		expected.directory = DefaultDirectory
	}

	if expected.directory != value.directory {
		t.Errorf("Expected directory %v, found %v", expected.directory, value.directory)
		return false
	}

	if expected.username != value.username {
		t.Errorf("Expected username %v, found %v", expected.username, value.password)
		return false
	}
	if expected.endpoints != nil && fmt.Sprint(expected.endpoints) != fmt.Sprint(value.endpoints) {
		t.Errorf("Expected endpoints %v, found %v", expected.endpoints, value.endpoints)
		return false
	}
	if expected.password != value.password {
		t.Errorf("Expected password %v, found %v", expected.password, value.password)
		return false
	}
	return true
}

func TestGetProvider(t *testing.T) {
	tests := []struct {
		addr  string
		valid bool
	}{
		{"etc://localhost", false},
		{"http://localhost", false},
		{"ftp://localhost", false},
		{"https://localhost", false},
		{"etcd://localhost", true},
		{"etcde://localhost", false},
		{"etcd:/localhost", false},
		{"etcd:localhost", false},
	}

	provider.Register("etcd", New)

	for i, test := range tests {
		pr, _ := provider.Get(test.addr)
		if test.valid {
			if _, ok := pr.(*Provider); !ok {
				t.Errorf("Test %d: expecting provider to be etcd.Provider", i)
			}
			if _, ok := pr.(provider.DynamicProvider); !ok {
				t.Errorf("Test %d: expecting provider to be dynamic provider", i)
			}
		} else {
			if _, ok := pr.(*Provider); ok {
				t.Errorf("Test %d: not expecting etcd.Provider", i)
			}
		}
	}
}
