package requestid

import (
	"fmt"

	"github.com/mholt/caddy"
	"github.com/nu7hatch/gouuid"
)

// IsActive - Is RequestID Active?
var IsActive = false

func init() {
	caddy.RegisterPlugin("request_id", caddy.Plugin{

		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {

	for c.Next() {

		if c.NextArg() {
			return c.ArgErr() //no arg expected.
		}

	}
	IsActive = true
	return nil
}

// UUID returns U4 UUID
func UUID() string {
	u4, err := uuid.NewV4()
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}

	return u4.String()
}
