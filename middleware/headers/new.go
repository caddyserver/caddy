package headers

import (
	"net/http"

	"github.com/mholt/caddy/middleware"
)

// New constructs and configures a new headers middleware instance.
func New(c middleware.Controller) (middleware.Middleware, error) {

	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		head := Headers{
			next:  next,
			rules: rules,
		}
		return head.ServeHTTP
	}, nil
}
