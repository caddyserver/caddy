package setup

import (
	"strconv"

	"github.com/mholt/caddy/middleware"
)

func parseRoller(c *Controller) (*middleware.LogRoller, error) {
	var size, age, keep int
	// This is kind of a hack to support nested blocks:
	// As we are already in a block: either log or errors,
	// c.nesting > 0 but, as soon as c meets a }, it thinks
	// the block is over and return false for c.NextBlock.
	for c.NextBlock() {
		what := c.Val()
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		value := c.Val()
		var err error
		switch what {
		case "size":
			size, err = strconv.Atoi(value)
		case "age":
			age, err = strconv.Atoi(value)
		case "keep":
			keep, err = strconv.Atoi(value)
		}
		if err != nil {
			return nil, err
		}
	}
	return &middleware.LogRoller{
		MaxSize:    size,
		MaxAge:     age,
		MaxBackups: keep,
		LocalTime:  true,
	}, nil
}
