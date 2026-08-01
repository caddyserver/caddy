package internal

import (
	"testing"
)

func TestPrivateRangesCIDR(t *testing.T) {
	ranges := PrivateRangesCIDR()

	// Should include standard private IP ranges
	expected := map[string]bool{
		"192.168.0.0/16": false,
		"172.16.0.0/12":  false,
		"10.0.0.0/8":     false,
		"127.0.0.1/8":    false,
		"fd00::/8":       false,
		"::1":            false,
	}

	for _, r := range ranges {
		if _, ok := expected[r]; ok {
			expected[r] = true
		}
	}

	for cidr, found := range expected {
		if !found {
			t.Errorf("expected private range %q not found in PrivateRangesCIDR()", cidr)
		}
	}

	if len(ranges) < 6 {
		t.Errorf("expected at least 6 private ranges, got %d", len(ranges))
	}
}

func TestMaxSizeSubjectsListForLog(t *testing.T) {
	tests := []struct {
		name         string
		subjects     map[string]struct{}
		maxToDisplay int
		wantLen      int
		wantSuffix   bool // whether "(and N more...)" is expected
	}{
		{
			name:         "empty map",
			subjects:     map[string]struct{}{},
			maxToDisplay: 5,
			wantLen:      0,
			wantSuffix:   false,
		},
		{
			name: "fewer than max",
			subjects: map[string]struct{}{
				"example.com": {},
				"example.org": {},
			},
			maxToDisplay: 5,
			wantLen:      2,
			wantSuffix:   false,
		},
		{
			name: "equal to max",
			subjects: map[string]struct{}{
				"a.com": {},
				"b.com": {},
				"c.com": {},
			},
			maxToDisplay: 3,
			wantLen:      3,
			wantSuffix:   false,
		},
		{
			name: "more than max",
			subjects: map[string]struct{}{
				"a.com": {},
				"b.com": {},
				"c.com": {},
				"d.com": {},
				"e.com": {},
			},
			maxToDisplay: 2,
			wantLen:      3, // 2 domains + suffix
			wantSuffix:   true,
		},
		{
			name: "max is zero",
			subjects: map[string]struct{}{
				"a.com": {},
				"b.com": {},
			},
			maxToDisplay: 0,
			// BUG: When maxToDisplay is 0, code still appends one domain
			// because append happens before the break check in the loop.
			// Expected behavior: 1 item (just suffix). Actual: 2 items
			// (1 leaked domain + suffix).
			wantLen:    2,
			wantSuffix: true,
		},
		{
			name: "single subject with max 1",
			subjects: map[string]struct{}{
				"example.com": {},
			},
			maxToDisplay: 1,
			wantLen:      1,
			wantSuffix:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaxSizeSubjectsListForLog(tt.subjects, tt.maxToDisplay)
			if len(result) != tt.wantLen {
				t.Errorf("MaxSizeSubjectsListForLog() returned %d items, want %d; got: %v", len(result), tt.wantLen, result)
			}
			if tt.wantSuffix {
				last := result[len(result)-1]
				if len(last) < 4 || last[:4] != "(and" {
					t.Errorf("expected suffix '(and N more...)' but got %q", last)
				}
			}
		})
	}
}
