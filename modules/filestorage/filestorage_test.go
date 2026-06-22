package filestorage

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestFileStorageCaddyModule(t *testing.T) {
	fs := FileStorage{}
	info := fs.CaddyModule()
	if info.ID != "caddy.storage.file_system" {
		t.Errorf("CaddyModule().ID = %q, want 'caddy.storage.file_system'", info.ID)
	}
	mod := info.New()
	if mod == nil {
		t.Error("New() should not return nil")
	}
}

func TestFileStorageCertMagicStorage(t *testing.T) {
	fs := FileStorage{Root: "/var/lib/caddy/certs"}
	storage, err := fs.CertMagicStorage()
	if err != nil {
		t.Fatalf("CertMagicStorage() error = %v", err)
	}
	if storage == nil {
		t.Fatal("CertMagicStorage() returned nil")
	}
}

func TestFileStorageCertMagicStorageEmptyRoot(t *testing.T) {
	fs := FileStorage{Root: ""}
	storage, err := fs.CertMagicStorage()
	if err != nil {
		t.Fatalf("CertMagicStorage() error = %v", err)
	}
	if storage == nil {
		t.Fatal("CertMagicStorage() returned nil even with empty root")
	}
}

func TestFileStorageUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantVal string
	}{
		{
			name:    "root as inline arg",
			input:   `file_system /var/lib/caddy`,
			wantVal: "/var/lib/caddy",
		},
		{
			name:    "root in block",
			input:   "file_system {\n\troot /var/lib/caddy\n}",
			wantVal: "/var/lib/caddy",
		},
		{
			name:    "missing root",
			input:   `file_system`,
			wantErr: true,
		},
		{
			name:    "too many inline args",
			input:   `file_system /path1 /path2`,
			wantErr: true,
		},
		{
			name:    "root already set inline then block",
			input:   "file_system /path1 {\n\troot /path2\n}",
			wantErr: true,
		},
		{
			name:    "unknown subdirective",
			input:   "file_system {\n\tunknown_option value\n}",
			wantErr: true,
		},
		{
			name:    "root in block without value",
			input:   "file_system {\n\troot\n}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			fs := &FileStorage{}
			err := fs.UnmarshalCaddyfile(d)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fs.Root != tt.wantVal {
				t.Errorf("Root = %q, want %q", fs.Root, tt.wantVal)
			}
		})
	}
}
