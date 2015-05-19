package setup

import (
	"crypto/tls"
	"log"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Map of supported protocols
// SSLv3 will be not supported in next release
var supportedProtocols = map[string]uint16{
	"ssl3.0": tls.VersionSSL30,
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
}

// Map of supported ciphers
// For security reasons caddy will not support RC4 ciphers
var supportedCiphers = map[string]uint16{
	"ECDHE-RSA-AES128-GCM-SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-ECDSA-AES128-GCM-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"ECDHE-RSA-AES128-CBC-SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES256-CBC-SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES256-CBC-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-ECDSA-AES128-CBC-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"RSA-AES128-CBC-SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"RSA-AES256-CBC-SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-3DES-EDE-CBC-SHA":    tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"RSA-3DES-EDE-CBC-SHA":          tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

func TLS(c *Controller) (middleware.Middleware, error) {
	c.TLS.Enabled = true
	if c.Port == "http" {
		c.TLS.Enabled = false
		log.Printf("Warning: TLS was disabled on host http://%s."+
			" Make sure you are specifying https://%s in your config (if you haven't already)."+
			" If you meant to serve tls on port 80,"+
			" specify port 80 in your config (https://%s:80).", c.Host, c.Host, c.Host)
	}

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		c.TLS.Certificate = c.Val()

		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		c.TLS.Key = c.Val()

		// Optional block
		for c.NextBlock() {
			switch c.Val() {
			case "protocols":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}
				value, ok := supportedProtocols[strings.ToLower(args[0])]
				if !ok {
					return nil, c.Errf("Wrong protocol name or protocol not supported '%s'", c.Val())

				}
				c.TLS.ProtocolMinVersion = value
				value, ok = supportedProtocols[strings.ToLower(args[1])]
				if !ok {
					return nil, c.Errf("Wrong protocol name or protocol not supported '%s'", c.Val())
				}
				c.TLS.ProtocolMaxVersion = value
			case "ciphers":
				for c.NextArg() {
					value, ok := supportedCiphers[strings.ToUpper(c.Val())]
					if !ok {
						return nil, c.Errf("Wrong cipher name or cipher not supported '%s'", c.Val())
					}
					c.TLS.Ciphers = append(c.TLS.Ciphers, value)
				}
			case "cache":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				size, err := strconv.Atoi(c.Val())
				if err != nil {
					return nil, c.Errf("Cache parameter should be an number '%s': %v", c.Val(), err)
				}
				c.TLS.CacheSize = size
			default:
				return nil, c.Errf("Unknown keyword '%s'")
			}
		}
	}

	// If no Ciphers provided, use all caddy supportedCiphers
	if len(c.TLS.Ciphers) == 0 {
		for _, v := range supportedCiphers {
			c.TLS.Ciphers = append(c.TLS.Ciphers, v)
		}
	}

	// If no ProtocolMin provided, set default MinVersion to TLSv1.1 for security reasons
	if c.TLS.ProtocolMinVersion == 0 {
		c.TLS.ProtocolMinVersion = tls.VersionTLS11
	}

	//If no ProtocolMax provided, use crypto/tls default MaxVersion(tls1.2)
	if c.TLS.ProtocolMaxVersion == 0 {
		c.TLS.ProtocolMaxVersion = tls.VersionTLS12
	}

	//If no cachesize provided, set default to 64
	if c.TLS.CacheSize == 0 {
		c.TLS.CacheSize = 64
	}

	return nil, nil
}
