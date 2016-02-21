package kvstore

import (
	"testing"
)

func TestKV(t *testing.T) {
	tests := []struct {
		url          string
		expectedType string
		expectedDir  string
	}{
		{
			"etcd://localhost:1000/dir",
			"etcd",
			"dir",
		},
		{
			"etcd://localhost:1000/",
			"etcd",
			DefaultDirectory,
		},
		{
			"consul://localhost:1000/dir",
			"consul",
			"dir",
		},
		{
			"consul://localhost:1000/",
			"consul",
			DefaultDirectory,
		},
		{
			"zk://localhost:1000/dir",
			"zk",
			"dir",
		},
		{
			"zk://localhost:1000/",
			"zk",
			DefaultDirectory,
		},
	}

	for i, test := range tests {
		s, _ := NewStore(test.url)
		if s.BaseDir != test.expectedDir {
			t.Errorf("Test %d: expected %s found %s", i, test.expectedDir, s.BaseDir)
		}
		if s.Type != test.expectedType {
			t.Errorf("Test %d: expected %s found %s", i, test.expectedType, s.Type)
		}
	}
}
