package setup

import "testing"

func TestPProf(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
	}{
		{`pprof`, false},
		{`pprof {}`, true},
		{`pprof /foo`, true},
		{`pprof {
            a b
        }`, true},
		{`pprof
          pprof`, true},
	}
	for i, test := range tests {
		c := NewTestController(test.input)
		_, err := PProf(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
