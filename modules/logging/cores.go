package logging

import (
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(MockCore{})
}

// MockCore is a no-op module, purely for testing
type MockCore struct {
	zapcore.Core `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (MockCore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.cores.mock",
		New: func() caddy.Module { return new(MockCore) },
	}
}

func (lec *MockCore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Interface guards
var (
	_ zapcore.Core          = (*MockCore)(nil)
	_ caddy.Module          = (*MockCore)(nil)
	_ caddyfile.Unmarshaler = (*MockCore)(nil)
)
