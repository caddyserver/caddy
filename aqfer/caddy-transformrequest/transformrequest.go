package transformrequest

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("transformrequest", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

func Setup(c *caddy.Controller) error {
	if c.Next() {
		// c.Next()

		cfg := httpserver.GetConfig(c)
		mid := func(next httpserver.Handler) httpserver.Handler {
			return &TransformrequestHandler{
				Next: next,
			}
		}
		cfg.AddMiddleware(mid)

		if len(c.RemainingArgs()) > 0 {
			return errors.New("TransformRequest recevied more arguments than expected")
		}
	}
	return nil
}

type TransformrequestHandler struct {
	Next httpserver.Handler
}

func (h TransformrequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if transformed, err := Transformations(r); err != nil {
		if strings.Contains(err.Error(), "Cid") {
			return 403, err
		} else {
			return 400, err
		}
	} else {
		return h.Next.ServeHTTP(w, transformed)
	}
}
