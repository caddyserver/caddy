// +build go1.8

package crypto

import "crypto/tls"

func maybeGetConfigForClient(c *tls.Config, sni string) (*tls.Config, error) {
	if c.GetConfigForClient == nil {
		return c, nil
	}
	return c.GetConfigForClient(&tls.ClientHelloInfo{
		ServerName: sni,
	})
}
