package caddytls

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

type PermissionByPath struct {
	RootPath string `json:"root_path"`

	logger   *zap.Logger
	replacer *caddy.Replacer
}

func (p PermissionByPath) CertificateAllowed(ctx context.Context, name string) error {
	askRooPath, err := p.replacer.ReplaceOrErr(p.RootPath, true, true)
	if err != nil {
		return fmt.Errorf("preparing 'ask' path: %v", err)
	}

	filePath := path.Join(askRooPath, name)
	if _, err := os.Stat(filePath); err != nil {
		return err
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (p *PermissionByPath) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return nil
	}
	if !d.AllArgs(&p.RootPath) {
		return d.ArgErr()
	}
	return nil
}

func (p *PermissionByPath) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	p.replacer = caddy.NewReplacer()
	return nil
}

func init() {
	caddy.RegisterModule(PermissionByPath{})
}

// CaddyModule returns the Caddy module information.
func (PermissionByPath) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.path",
		New: func() caddy.Module { return new(PermissionByPath) },
	}
}

// Interface guards
var (
	_ OnDemandPermission = (*PermissionByPath)(nil)
	_ caddy.Provisioner  = (*PermissionByPath)(nil)
)
