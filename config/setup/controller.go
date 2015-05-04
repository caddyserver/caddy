package setup

import (
	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/server"
)

type Controller struct {
	*server.Config
	parse.Dispenser
}
