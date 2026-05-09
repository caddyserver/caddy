package caddytls

import (
	"testing"
)

func TestManagingWildcardFor(t *testing.T) {
	tlsApp := &TLS{
		managing:      make(map[string]string),
		automateNames: make(map[string]struct{}),
	}

	tests := []struct {
		name               string
		subj               string
		otherSubjs         map[string]struct{}
		setup              func()
		expected           bool
	}{
		{
			name: "managed in t.managing",
			subj: "sub.example.com",
			otherSubjs: nil,
			setup: func() {
				tlsApp.managing = map[string]string{"*.example.com": ""}
				tlsApp.automateNames = make(map[string]struct{})
			},
			expected: true,
		},
		{
			name: "managed in otherSubjsToManage",
			subj: "sub.example.com",
			otherSubjs: map[string]struct{}{"*.example.com": {}},
			setup: func() {
				tlsApp.managing = make(map[string]string)
				tlsApp.automateNames = make(map[string]struct{})
			},
			expected: true,
		},
		{
			name: "managed in t.automateNames (fixes race condition)",
			subj: "sg.jf.p.rijul.me",
			otherSubjs: map[string]struct{}{"sg.jf.p.rijul.me": {}},
			setup: func() {
				tlsApp.managing = make(map[string]string)
				tlsApp.automateNames = map[string]struct{}{"*.jf.p.rijul.me": {}}
			},
			expected: true,
		},
		{
			name: "no wildcard managed",
			subj: "sub.example.com",
			otherSubjs: map[string]struct{}{"sub.example.com": {}},
			setup: func() {
				tlsApp.managing = make(map[string]string)
				tlsApp.automateNames = make(map[string]struct{})
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			actual := tlsApp.managingWildcardFor(tc.subj, tc.otherSubjs)
			if actual != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, actual)
			}
		})
	}
}
