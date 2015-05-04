package setup

import (
	"os"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/extensions"
)

// Ext configures a new instance of 'extensions' middleware for clean URLs.
func Ext(c *Controller) (middleware.Middleware, error) {
	root := c.Root

	exts, err := extParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return extensions.Ext{
			Next:       next,
			Extensions: exts,
			Root:       root,
		}
	}, nil
}

// extParse sets up an instance of extension middleware
// from a middleware controller and returns a list of extensions.
func extParse(c *Controller) ([]string, error) {
	var exts []string

	for c.Next() {
		// At least one extension is required
		if !c.NextArg() {
			return exts, c.ArgErr()
		}
		exts = append(exts, c.Val())

		// Tack on any other extensions that may have been listed
		exts = append(exts, c.RemainingArgs()...)
	}

	return exts, nil
}

// resourceExists returns true if the file specified at
// root + path exists; false otherwise.
func resourceExists(root, path string) bool {
	_, err := os.Stat(root + path)
	// technically we should use os.IsNotExist(err)
	// but we don't handle any other kinds of errors anyway
	return err == nil
}
