package integration

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// (see https://github.com/caddyserver/caddy/issues/3556 for use case)
func TestH2ToH2CStream(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(` 
  {
	"admin": {
		"listen": "localhost:2999"
	},
    "apps": {
      "http": {
        "http_port": 9080,
        "https_port": 9443,
		"grace_period": 1,
        "servers": {
          "srv0": {
            "listen": [
              ":9443"
            ],
            "routes": [
              {
                "handle": [
                  {
                    "handler": "reverse_proxy",
                    "transport": {
                      "protocol": "http",
                      "compression": false,
                      "versions": [
                        "h2c",
                        "2"
                      ]
                    },
                    "upstreams": [
                      {
                        "dial": "localhost:54321"
                      }
                    ]
                  }
                ],
                "match": [
                  {
                    "path": [
                      "/tov2ray"
                    ]
                  }
                ]
              }
            ],
            "tls_connection_policies": [
              {
                "certificate_selection": {
                  "any_tag": ["cert0"]
                },
                "default_sni": "a.caddy.localhost"
              }
            ]
          }
        }
      },
      "tls": {
        "certificates": {
          "load_files": [
            {
              "certificate": "/a.caddy.localhost.crt",
              "key": "/a.caddy.localhost.key",
              "tags": [
                "cert0"
              ]
            }
          ]
        }
      },
      "pki": {
        "certificate_authorities" : {
          "local" : {
            "install_trust": false
          }
        }
      }
    }
  }
  `, "json")

	expectedBody := "some data to be echoed"
	// start the server
	server := testH2ToH2CStreamServeH2C(t)
	go server.ListenAndServe()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		server.Shutdown(ctx)
	}()

	r, w := io.Pipe()
	req := &http.Request{
		Method: "PUT",
		Body:   io.NopCloser(r),
		URL: &url.URL{
			Scheme: "https",
			Host:   "127.0.0.1:9443",
			Path:   "/tov2ray",
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     make(http.Header),
	}
	// Disable any compression method from server.
	req.Header.Set("Accept-Encoding", "identity")

	resp := tester.AssertResponseCode(req, http.StatusOK)
	if resp.StatusCode != http.StatusOK {
		return
	}
	go func() {
		fmt.Fprint(w, expectedBody)
		w.Close()
	}()

	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unable to read the response body %s", err)
	}

	body := string(bytes)

	if !strings.Contains(body, expectedBody) {
		t.Errorf("requesting \"%s\" expected response body \"%s\" but got \"%s\"", req.RequestURI, expectedBody, body)
	}
}

func testH2ToH2CStreamServeH2C(t *testing.T) *http.Server {
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rstring, err := httputil.DumpRequest(r, false)
		if err == nil {
			t.Logf("h2c server received req: %s", rstring)
		}
		// We only accept HTTP/2!
		if r.ProtoMajor != 2 {
			t.Error("Not a HTTP/2 request, rejected!")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if r.Host != "127.0.0.1:9443" {
			t.Errorf("r.Host doesn't match, %v!", r.Host)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if !strings.HasPrefix(r.URL.Path, "/tov2ray") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		http.NewResponseController(w).Flush()

		buf := make([]byte, 4*1024)

		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}

			if err != nil {
				if err == io.EOF {
					r.Body.Close()
				}
				break
			}
		}
	})

	server := &http.Server{
		Addr:    "127.0.0.1:54321",
		Handler: h2c.NewHandler(handler, h2s),
	}
	return server
}

// (see https://github.com/caddyserver/caddy/issues/3606 for use case)
func TestH2ToH1ChunkedResponse(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(` 
{
	"admin": {
		"listen": "localhost:2999"
	},
  "logging": {
    "logs": {
      "default": {
        "level": "DEBUG"
      }
    }
  },
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
	  "grace_period": 1,
      "servers": {
        "srv0": {
          "listen": [
            ":9443"
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
                          "encodings": {
                            "gzip": {}
                          },
                          "handler": "encode"
                        }
                      ]
                    },
                    {
                      "handle": [
                        {
                          "handler": "reverse_proxy",
                          "upstreams": [
                            {
                              "dial": "localhost:54321"
                            }
                          ]
                        }
                      ],
                      "match": [
                        {
                          "path": [
                            "/tov2ray"
                          ]
                        }
                      ]
                    }
                  ]
                }
              ],
              "terminal": true
            }
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {
                "any_tag": [
                  "cert0"
                ]
              },
              "default_sni": "a.caddy.localhost"
            }
          ]
        }
      }
    },
    "tls": {
      "certificates": {
        "load_files": [
          {
            "certificate": "/a.caddy.localhost.crt",
            "key": "/a.caddy.localhost.key",
            "tags": [
              "cert0"
            ]
          }
        ]
      }
    },
    "pki": {
      "certificate_authorities": {
        "local": {
          "install_trust": false
        }
      }
    }
  }
}
  `, "json")

	// need a large body here to trigger caddy's compression, larger than gzip.miniLength
	expectedBody, err := GenerateRandomString(1024)
	if err != nil {
		t.Fatalf("generate expected body failed, err: %s", err)
	}

	// start the server
	server := testH2ToH1ChunkedResponseServeH1(t)
	go server.ListenAndServe()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		server.Shutdown(ctx)
	}()

	r, w := io.Pipe()
	req := &http.Request{
		Method: "PUT",
		Body:   io.NopCloser(r),
		URL: &url.URL{
			Scheme: "https",
			Host:   "127.0.0.1:9443",
			Path:   "/tov2ray",
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     make(http.Header),
	}
	// underlying transport will automatically add gzip
	// req.Header.Set("Accept-Encoding", "gzip")
	go func() {
		fmt.Fprint(w, expectedBody)
		w.Close()
	}()
	resp := tester.AssertResponseCode(req, http.StatusOK)
	if resp.StatusCode != http.StatusOK {
		return
	}

	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unable to read the response body %s", err)
	}

	body := string(bytes)

	if body != expectedBody {
		t.Errorf("requesting \"%s\" expected response body \"%s\" but got \"%s\"", req.RequestURI, expectedBody, body)
	}
}

func testH2ToH1ChunkedResponseServeH1(t *testing.T) *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:9443" {
			t.Errorf("r.Host doesn't match, %v!", r.Host)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if !strings.HasPrefix(r.URL.Path, "/tov2ray") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		defer r.Body.Close()
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("unable to read the response body %s", err)
		}

		n := len(bytes)

		var writer io.Writer
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			gw, err := gzip.NewWriterLevel(w, 5)
			if err != nil {
				t.Error("can't return gzip data")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer gw.Close()
			writer = gw
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Del("Content-Length")
			w.WriteHeader(200)
		} else {
			writer = w
		}
		if n > 0 {
			writer.Write(bytes[:])
		}
	})

	server := &http.Server{
		Addr:    "127.0.0.1:54321",
		Handler: handler,
	}
	return server
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}
