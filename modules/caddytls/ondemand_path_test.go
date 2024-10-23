package caddytls

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestOnDemandPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*caddy.test")
	if err != nil {
		t.Fatalf("Cannot make a temp directory: %s", err.Error())
	}

	defer os.RemoveAll(tempDir) // clean up

	permissionByPath := PermissionByPath{RootPath: tempDir}
	if err := permissionByPath.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Errorf("Error Provisioning: %s", err.Error())
	}

	if err := permissionByPath.CertificateAllowed(context.Background(), "example.com"); err == nil {
		t.Errorf("Cert check should have failed")
	}

	os.MkdirAll(path.Join(tempDir, "example.com"), 0777)
	if err := permissionByPath.CertificateAllowed(context.Background(), "example.com"); err != nil {
		t.Errorf("Cert check should have succeeded: %s", err.Error())
	}
}
