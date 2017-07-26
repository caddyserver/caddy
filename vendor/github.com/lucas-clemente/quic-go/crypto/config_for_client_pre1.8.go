// +build !go1.8

package crypto

import "crypto/tls"

func maybeGetConfigForClient(c *tls.Config, sni string) (*tls.Config, error) {
	return c, nil
}
