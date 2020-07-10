package integration

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
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

func TestH2ToH2CStream(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(` 
  {
    "apps": {
      "http": {
        "http_port": 9080,
        "https_port": 9443,
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
		// Host:   httpSettings.getRandomHost(),
		Body: ioutil.NopCloser(r),
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

	resp := tester.AssertResponseCode(req, 200)
	if 200 != resp.StatusCode {
		return
	}
	go func() {
		fmt.Fprint(w, expectedBody)
		w.Close()
	}()

	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unable to read the response body %s", err)
	}

	body := string(bytes)

	if !strings.Contains(body, expectedBody) {
		t.Errorf("requesting \"%s\" expected response body \"%s\" but got \"%s\"", req.RequestURI, expectedBody, body)
	}
	return
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
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

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
