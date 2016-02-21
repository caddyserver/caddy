package provider

import (
	"testing"
	"time"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		addr  string
		valid bool
	}{
		{"etc://localhost", false},
		{"http://localhost", false},
		{"ftp://localhost", false},
		{"https://localhost", false},
		{"fake://localhost", true},
		{"faked://localhost", false},
	}

	Register("fake", func(s string) (Provider, error) {
		return fakeProvider(s), nil
	})

	for i, test := range tests {
		pr, _ := Get(test.addr)
		if test.valid {
			if _, ok := pr.(fakeProvider); !ok {
				t.Errorf("Test %d: expecting provider to be fakeProvider", i)
			}
			if _, ok := pr.(Provider); !ok {
				t.Errorf("Test %d: expecting provider to be provider", i)
			}
		} else {
			if _, ok := pr.(fakeProvider); ok {
				t.Errorf("Test %d: not expecting fakeProvider", i)
			}
		}
	}

	Register("fake", func(s string) (Provider, error) {
		return fakeDynamic{fakeProvider(s)}, nil
	})

	for i, test := range tests {
		pr, _ := Get(test.addr)
		if test.valid {
			if _, ok := pr.(fakeDynamic); !ok {
				t.Errorf("Test %d: expecting provider to be fakeDynamic", i)
			}
			if _, ok := pr.(DynamicProvider); !ok {
				t.Errorf("Test %d: expecting provider to be dynamic provider", i)
			}
		} else {
			if _, ok := pr.(fakeDynamic); ok {
				t.Errorf("Test %d: not expecting fakeDynamic", i)
			}
		}
	}

	tests = []struct {
		addr  string
		valid bool
	}{
		{"etc://localhost", false},
		{"http://localhost", true},
		{"ftp://localhost", false},
		{"https://localhost", true},
		{"localhost", true},
		{"http://localhost", true},
		{"faked://localhost", false},
	}

	Register("http", static)
	Register("https", static)
	Register("", static)

	for i, test := range tests {
		pr, _ := Get(test.addr)
		if test.valid {
			if _, ok := pr.(staticProvider); !ok {
				t.Errorf("Test %d: expecting provider to be staticProvider", i)
			}
			if _, ok := pr.(Provider); !ok {
				t.Errorf("Test %d: expecting provider to be provider", i)
			}
		} else {
			if _, ok := pr.(staticProvider); ok {
				t.Errorf("Test %d: not expecting staticProvider", i)
			}
		}
	}

}

type fakeProvider string

func (f fakeProvider) Hosts() ([]string, error) {
	return []string{string(f)}, nil
}

type fakeDynamic struct {
	fakeProvider
}

func (f fakeDynamic) Watch() Watcher {
	return f
}

func (f fakeDynamic) Next() (msgs []WatcherMsg, err error) {
	time.Sleep(100)
	return []WatcherMsg{}, nil
}
