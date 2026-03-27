package integration

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestLeafCertLifetimeLessThanIntermediate(t *testing.T) {
	caddytest.AssertLoadError(t, `
    {
      "admin": {
        "disabled": true
      },
      "apps": {
        "http": {
          "servers": {
            "srv0": {
              "listen": [
                ":443"
              ],
              "routes": [
                {
                  "handle": [
                    {
                      "handler": "subroute",
                      "routes": [
                        {
                          "handle": [
                            {
                              "ca": "internal",
                              "handler": "acme_server",
                              "lifetime": 604800000000000
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        },
        "pki": {
          "certificate_authorities": {
            "internal": {
              "install_trust": false,
              "intermediate_lifetime": 604800000000000,
              "name": "Internal CA"
            }
          }
        }
      }
    }
  `, "json", "should be less than intermediate certificate lifetime")
}

func TestIntermediateLifetimeLessThanRoot(t *testing.T) {
	caddytest.AssertLoadError(t, `
    {
      "admin": {
        "disabled": true
      },
      "apps": {
        "http": {
          "servers": {
            "srv0": {
              "listen": [
                ":443"
              ],
              "routes": [
                {
                  "handle": [
                    {
                      "handler": "subroute",
                      "routes": [
                        {
                          "handle": [
                            {
                              "ca": "internal",
                              "handler": "acme_server",
                              "lifetime": 2592000000000000
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        },
        "pki": {
          "certificate_authorities": {
            "internal": {
              "install_trust": false,
              "intermediate_lifetime": 311040000000000000,
              "name": "Internal CA"
            }
          }
        }
      }
    }
  `, "json", "intermediate certificate lifetime must be less than actual root certificate lifetime")
}
