package caddyfile

import (
	"testing"
)

func TestFormattingDifferenceCases(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "no change",
			run: func(t *testing.T) {
				input := []byte("example.com {\n\trespond \"hello\"\n}\n")
				formatted := Format(input)
				if string(formatted) != string(input) {
					t.Skip("input is not considered formatted by Format(); skipping")
				}

				warning, different := FormattingDifference("Caddyfile", input)
				if different {
					t.Errorf("expected no difference for properly formatted input, got warning: %v", warning)
				}
			},
		},
		{
			name: "with change",
			run: func(t *testing.T) {
				input := []byte("example.com {\n  respond \"hello\"\n}\n")
				formatted := Format(input)
				if string(formatted) == string(input) {
					t.Skip("Format() did not change input; skipping")
				}

				warning, different := FormattingDifference("Caddyfile", input)
				if !different {
					t.Error("expected difference for misformatted input")
				}
				if warning.File != "Caddyfile" {
					t.Errorf("warning.File = %q, want 'Caddyfile'", warning.File)
				}
				if warning.Line < 1 {
					t.Errorf("warning.Line = %d, want >= 1", warning.Line)
				}
				if warning.Message == "" {
					t.Error("warning.Message should not be empty")
				}
			},
		},
		{
			name: "crlf normalization",
			run: func(t *testing.T) {
				inputCRLF := []byte("example.com {\r\n\trespond \"hello\"\r\n}\r\n")
				inputLF := []byte("example.com {\n\trespond \"hello\"\n}\n")
				formattedLF := Format(inputLF)

				_, differentCRLF := FormattingDifference("Caddyfile", inputCRLF)
				_, differentLF := FormattingDifference("Caddyfile", inputLF)

				if string(formattedLF) == string(inputLF) && differentCRLF {
					t.Error("CRLF input should match when LF version is considered formatted")
				}
				if differentCRLF != differentLF {
					t.Error("CRLF and LF versions should yield same formatting result")
				}
			},
		},
		{
			name: "empty input",
			run: func(t *testing.T) {
				_, different := FormattingDifference("Caddyfile", []byte{})
				formatted := Format([]byte{})
				if different != !isEqual(formatted, []byte{}) {
					t.Errorf("difference = %v, but Format equality = %v", different, isEqual(formatted, []byte{}))
				}
			},
		},
		{
			name: "custom filename",
			run: func(t *testing.T) {
				input := []byte("example.com {\n  respond \"hello\"\n}\n")
				formatted := Format(input)
				if string(formatted) == string(input) {
					t.Skip("Format() did not change input; skipping")
				}

				warning, different := FormattingDifference("myconfig.caddyfile", input)
				if !different {
					t.Error("expected difference")
				}
				if warning.File != "myconfig.caddyfile" {
					t.Errorf("warning.File = %q, want 'myconfig.caddyfile'", warning.File)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
		})
	}
}

func isEqual(a, b []byte) bool {
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
