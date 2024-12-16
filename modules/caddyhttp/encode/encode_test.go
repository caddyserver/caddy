package encode

import (
	"net/http"
	"sync"
	"testing"
)

func BenchmarkOpenResponseWriter(b *testing.B) {
	enc := new(Encode)
	for n := 0; n < b.N; n++ {
		enc.openResponseWriter("test", nil, false)
	}
}

func TestPreferOrder(t *testing.T) {
	testCases := []struct {
		name     string
		accept   string
		prefer   []string
		expected []string
	}{
		{
			name:     "PreferOrder(): 4 accept, 3 prefer",
			accept:   "deflate, gzip, br, zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): 2 accept, 3 prefer",
			accept:   "deflate, zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "deflate"},
		},
		{
			name:     "PreferOrder(): 2 accept (1 empty), 3 prefer",
			accept:   "gzip,,zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "gzip", ""},
		},
		{
			name:     "PreferOrder(): 1 accept, 2 prefer",
			accept:   "gzip",
			prefer:   []string{"zstd", "gzip"},
			expected: []string{"gzip"},
		},
		{
			name:     "PreferOrder(): 4 accept (1 duplicate), 1 prefer",
			accept:   "deflate, gzip, br, br",
			prefer:   []string{"br"},
			expected: []string{"br", "br", "deflate", "gzip"},
		},
		{
			name:     "PreferOrder(): empty accept, 0 prefer",
			accept:   "",
			prefer:   []string{},
			expected: []string{},
		},
		{
			name:     "PreferOrder(): empty accept, 1 prefer",
			accept:   "",
			prefer:   []string{"gzip"},
			expected: []string{},
		},
		{
			name:     "PreferOrder(): with q-factor",
			accept:   "deflate;q=0.8, gzip;q=0.4, br;q=0.2, zstd",
			prefer:   []string{"gzip"},
			expected: []string{"zstd", "deflate", "gzip", "br"},
		},
		{
			name:     "PreferOrder(): with q-factor, no prefer",
			accept:   "deflate;q=0.8, gzip;q=0.4, br;q=0.2, zstd",
			prefer:   []string{},
			expected: []string{"zstd", "deflate", "gzip", "br"},
		},
		{
			name:     "PreferOrder(): q-factor=0 filtered out",
			accept:   "deflate;q=0.1, gzip;q=0.4, br;q=0.5, zstd;q=0",
			prefer:   []string{"gzip"},
			expected: []string{"br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): q-factor=0 filtered out, no prefer",
			accept:   "deflate;q=0.1, gzip;q=0.4, br;q=0.5, zstd;q=0",
			prefer:   []string{},
			expected: []string{"br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): with invalid q-factor",
			accept:   "br, deflate, gzip;q=2, zstd;q=0.1",
			prefer:   []string{"zstd", "gzip"},
			expected: []string{"gzip", "br", "deflate", "zstd"},
		},
		{
			name:     "PreferOrder(): with invalid q-factor, no prefer",
			accept:   "br, deflate, gzip;q=2, zstd;q=0.1",
			prefer:   []string{},
			expected: []string{"br", "deflate", "gzip", "zstd"},
		},
	}

	enc := new(Encode)
	r, _ := http.NewRequest("", "", nil)

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if test.accept == "" {
				r.Header.Del("Accept-Encoding")
			} else {
				r.Header.Set("Accept-Encoding", test.accept)
			}
			enc.Prefer = test.prefer
			result := AcceptedEncodings(r, enc.Prefer)
			if !sliceEqual(result, test.expected) {
				t.Errorf("AcceptedEncodings() actual: %s expected: %s",
					result,
					test.expected)
			}
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestValidate(t *testing.T) {
	type testCase struct {
		name    string
		prefer  []string
		wantErr bool
	}

	var err error
	var testCases []testCase
	enc := new(Encode)

	enc.writerPools = map[string]*sync.Pool{
		"zstd": nil,
		"gzip": nil,
		"br":   nil,
	}
	testCases = []testCase{
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with all encoder",
			prefer:  []string{"zstd", "br", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with 2 out of 3 encoders",
			prefer:  []string{"br", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with 1 out of 3 encoders",
			prefer:  []string{"gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): 1 duplicated (once) encoder",
			prefer:  []string{"gzip", "zstd", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): 1 not enabled encoder in prefer list",
			prefer:  []string{"br", "zstd", "gzip", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): no prefer list",
			prefer:  []string{},
			wantErr: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			enc.Prefer = test.prefer
			err = enc.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}

	enc.writerPools = map[string]*sync.Pool{
		"zstd": nil,
		"gzip": nil,
	}
	testCases = []testCase{
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 not enabled encoder in prefer list",
			prefer:  []string{"zstd", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 2 not enabled encoder in prefer list",
			prefer:  []string{"br", "zstd", "gzip", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): only not enabled encoder in prefer list",
			prefer:  []string{"deflate", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated (once) encoder in prefer list",
			prefer:  []string{"gzip", "zstd", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated (twice) encoder in prefer list",
			prefer:  []string{"gzip", "zstd", "gzip", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated encoder in prefer list",
			prefer:  []string{"zstd", "zstd", "gzip", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated not enabled encoder in prefer list",
			prefer:  []string{"br", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 2 duplicated not enabled encoder in prefer list",
			prefer:  []string{"br", "deflate", "br", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): valid order zstd first",
			prefer:  []string{"zstd", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): valid order gzip first",
			prefer:  []string{"gzip", "zstd"},
			wantErr: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			enc.Prefer = test.prefer
			err = enc.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestIsEncodeAllowed(t *testing.T) {
	testCases := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name:     "Without any headers",
			headers:  http.Header{},
			expected: true,
		},
		{
			name: "Without Cache-Control HTTP header",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
			},
			expected: true,
		},
		{
			name: "Cache-Control HTTP header ending with no-transform directive",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
				"Cache-Control":   {"no-cache; no-transform"},
			},
			expected: false,
		},
		{
			name: "With Cache-Control HTTP header no-transform as Cache-Extension value",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
				"Cache-Control":   {`no-store; no-cache; community="no-transform"`},
			},
			expected: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if result := isEncodeAllowed(test.headers); result != test.expected {
				t.Errorf("The headers given to the isEncodeAllowed should return %t, %t given.",
					result,
					test.expected)
			}
		})
	}
}
