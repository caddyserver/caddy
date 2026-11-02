package internal

import (
	"io/fs"
	"testing"
)

func TestSplitUnixSocketPermissionsBits(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantPath     string
		wantFileMode fs.FileMode
		wantErr      bool
	}{
		{
			name:         "no permission bits defaults to 0200",
			input:        "/run/caddy.sock",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o200,
			wantErr:      false,
		},
		{
			name:         "valid permission 0222",
			input:        "/run/caddy.sock|0222",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o222,
			wantErr:      false,
		},
		{
			name:         "valid permission 0200",
			input:        "/run/caddy.sock|0200",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o200,
			wantErr:      false,
		},
		{
			name:         "valid permission 0777",
			input:        "/run/caddy.sock|0777",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o777,
			wantErr:      false,
		},
		{
			name:         "valid permission 0755",
			input:        "/run/caddy.sock|0755",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o755,
			wantErr:      false,
		},
		{
			name:         "valid permission 0666",
			input:        "/tmp/test.sock|0666",
			wantPath:     "/tmp/test.sock",
			wantFileMode: 0o666,
			wantErr:      false,
		},
		{
			name:    "missing owner write permission 0444",
			input:   "/run/caddy.sock|0444",
			wantErr: true,
		},
		{
			name:    "missing owner write permission 0044",
			input:   "/run/caddy.sock|0044",
			wantErr: true,
		},
		{
			name:    "missing owner write permission 0100",
			input:   "/run/caddy.sock|0100",
			wantErr: true,
		},
		{
			name:    "missing owner write permission 0500",
			input:   "/run/caddy.sock|0500",
			wantErr: true,
		},
		{
			name:    "invalid octal digits",
			input:   "/run/caddy.sock|09ab",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric permission",
			input:   "/run/caddy.sock|rwxrwxrwx",
			wantErr: true,
		},
		{
			name:    "empty permission string",
			input:   "/run/caddy.sock|",
			wantErr: true,
		},
		{
			name:         "multiple pipes only splits on first",
			input:        "/run/caddy|sock|0222",
			wantPath:     "/run/caddy",
			wantFileMode: 0, // "sock|0222" is not valid octal
			wantErr:      true,
		},
		{
			name:         "empty path with valid permission",
			input:        "|0222",
			wantPath:     "",
			wantFileMode: 0o222,
			wantErr:      false,
		},
		{
			name:         "path only with no pipe",
			input:        "/var/run/my-app.sock",
			wantPath:     "/var/run/my-app.sock",
			wantFileMode: 0o200,
			wantErr:      false,
		},
		{
			name:         "permission 0300 has write bit",
			input:        "/run/caddy.sock|0300",
			wantPath:     "/run/caddy.sock",
			wantFileMode: 0o300,
			wantErr:      false,
		},
		{
			name:    "permission 0422 missing owner write",
			input:   "/run/caddy.sock|0422",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotMode, err := SplitUnixSocketPermissionsBits(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitUnixSocketPermissionsBits(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotPath != tt.wantPath {
				t.Errorf("SplitUnixSocketPermissionsBits(%q) path = %q, want %q", tt.input, gotPath, tt.wantPath)
			}
			if gotMode != tt.wantFileMode {
				t.Errorf("SplitUnixSocketPermissionsBits(%q) mode = %04o, want %04o", tt.input, gotMode, tt.wantFileMode)
			}
		})
	}
}
