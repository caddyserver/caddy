package caddycmd

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
)

func TestImportStorageArchive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      string
		typeflag byte
		wantErr  bool
	}{
		{name: "regular", key: "certificates/example.com/cert.pem", typeflag: tar.TypeReg},
		{name: "legacy regular", key: "certificates/example.com/cert.pem", typeflag: 0},
		{name: "parent", key: "../../escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "embedded parent", key: "dir/../escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "absolute", key: "/escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "backslash", key: `..\escaped-proof.txt`, typeflag: tar.TypeReg, wantErr: true},
		{name: "drive", key: "C:/escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "drive relative", key: "C:escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "alternate stream", key: "cert.pem:stream", typeflag: tar.TypeReg, wantErr: true},
		{name: "dot", key: ".", typeflag: tar.TypeReg, wantErr: true},
		{name: "dot component", key: "dir/./cert.pem", typeflag: tar.TypeReg, wantErr: true},
		{name: "dot prefix parent", key: "./../escaped-proof.txt", typeflag: tar.TypeReg, wantErr: true},
		{name: "double dot prefix", key: "././cert.pem", typeflag: tar.TypeReg, wantErr: true},
		{name: "empty component", key: "dir//cert.pem", typeflag: tar.TypeReg, wantErr: true},
		{name: "symlink", key: "link", typeflag: tar.TypeSymlink, wantErr: true},
		{name: "hardlink", key: "link", typeflag: tar.TypeLink, wantErr: true},
		{name: "fifo", key: "fifo", typeflag: tar.TypeFifo, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stor := &certmagic.FileStorage{Path: filepath.Join(dir, "storage", "inner")}
			oldStorage := caddy.DefaultStorage
			caddy.DefaultStorage = stor
			t.Cleanup(func() { caddy.DefaultStorage = oldStorage })

			var archive bytes.Buffer
			tw := tar.NewWriter(&archive)
			hdr := &tar.Header{Name: tc.key, Typeflag: tc.typeflag, Mode: 0o600}
			const contents = "archive contents"
			if tc.typeflag == tar.TypeReg || tc.typeflag == 0 {
				hdr.Size = int64(len(contents))
			}
			if tc.typeflag == tar.TypeSymlink || tc.typeflag == tar.TypeLink {
				hdr.Linkname = "../../escaped-proof.txt"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if hdr.Size > 0 {
				if _, err := tw.Write([]byte(contents)); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(dir, "input.tar")
			writeTestFile(t, input, archive.String())
			config := filepath.Join(dir, "config.json")
			writeTestFile(t, config, "{}")
			flags := pflag.NewFlagSet("import", pflag.ContinueOnError)
			flags.String("config", config, "")
			flags.String("input", input, "")
			_, code, err := captureStdout(t, func() (int, error) {
				return cmdImportStorage(Flags{flags})
			})
			if tc.wantErr {
				if err == nil || code != caddy.ExitCodeFailedQuit {
					t.Fatalf("expected rejected entry, got code %d, error %v", code, err)
				}
				if _, err := os.Stat(stor.Path); !os.IsNotExist(err) {
					t.Fatalf("rejected archive created storage: %v", err)
				}
				if _, err := os.Stat(filepath.Join(dir, "escaped-proof.txt")); !os.IsNotExist(err) {
					t.Fatalf("archive escaped storage: %v", err)
				}
				return
			}
			if err != nil || code != caddy.ExitCodeSuccess {
				t.Fatalf("import failed: code %d, error %v", code, err)
			}
			got, err := stor.Load(context.Background(), tc.key)
			if err != nil || string(got) != contents {
				t.Fatalf("imported contents %q, error %v", got, err)
			}

			output := filepath.Join(dir, "output.tar")
			exportFlags := pflag.NewFlagSet("export", pflag.ContinueOnError)
			exportFlags.String("config", config, "")
			exportFlags.String("output", output, "")
			if code, err := cmdExportStorage(Flags{exportFlags}); err != nil || code != caddy.ExitCodeSuccess {
				t.Fatalf("export failed: code %d, error %v", code, err)
			}
			outputFile, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			exportedHeader, err := tar.NewReader(outputFile).Next()
			outputFile.Close()
			if err != nil {
				t.Fatal(err)
			}
			if exportedHeader.Name != tc.key {
				t.Fatalf("exported archive key %q, want %q", exportedHeader.Name, tc.key)
			}
			if err := flags.Set("input", output); err != nil {
				t.Fatal(err)
			}
			stor.Path = filepath.Join(dir, "restored")
			if _, _, err := captureStdout(t, func() (int, error) {
				return cmdImportStorage(Flags{flags})
			}); err != nil {
				t.Fatal(err)
			}
			got, err = stor.Load(context.Background(), tc.key)
			if err != nil || string(got) != contents {
				t.Fatalf("round-trip contents %q, error %v", got, err)
			}
		})
	}
}

func TestImportStorageArchiveFromTar(t *testing.T) {
	dir := t.TempDir()
	stor := &certmagic.FileStorage{Path: filepath.Join(dir, "storage")}
	oldStorage := caddy.DefaultStorage
	caddy.DefaultStorage = stor
	t.Cleanup(func() { caddy.DefaultStorage = oldStorage })

	// mimic `tar -C storage -cf archive.tar .`
	const contents = "archive contents"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, hdr := range []*tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "./certificates/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "./certificates/example.com/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "./certificates/example.com/cert.pem", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(contents))},
	} {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input.tar")
	writeTestFile(t, input, archive.String())
	config := filepath.Join(dir, "config.json")
	writeTestFile(t, config, "{}")
	flags := pflag.NewFlagSet("import", pflag.ContinueOnError)
	flags.String("config", config, "")
	flags.String("input", input, "")
	if _, code, err := captureStdout(t, func() (int, error) {
		return cmdImportStorage(Flags{flags})
	}); err != nil || code != caddy.ExitCodeSuccess {
		t.Fatalf("import failed: code %d, error %v", code, err)
	}
	got, err := stor.Load(context.Background(), "certificates/example.com/cert.pem")
	if err != nil || string(got) != contents {
		t.Fatalf("imported contents %q, error %v", got, err)
	}
	keys, err := stor.List(context.Background(), "", true)
	if err != nil || len(keys) != 3 {
		t.Fatalf("stored keys %v, error %v", keys, err)
	}
}
