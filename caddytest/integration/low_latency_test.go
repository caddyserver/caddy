package integration

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyLowLatencyStreaming(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
  "logging": {
    "logs": {
      "default": {
        "level": "DEBUG",
        "writer": {
          "output": "stdout"
        }
      }
    }
  },
	"admin": {
		"listen": "localhost:2999"
	},
  "apps": {
    "http": {
      "grace_period": "60s",
      "servers": {
        "files": {
          "listen": [":8881"],
          "routes": [{
            "match": [ { "host": ["*"]}],
            "handle": [{"handler": "file_server", "root": "/tmp", "browse": {}}]
          }],
          "automatic_https": {
            "disable": true
          }
        },
        "public": {
          "listen": [
            ":8880"
          ],
          "routes": [
            {
              "match": [
                {
                  "host": [
                    "*"
                  ]
                }
              ],
              "handle": [
                {
                  "handler": "reverse_proxy",
									"close_after_received_body": true,
                  "headers": {
                    "request": {
                      "set": {
                        "X-Server-Name": [
                          "test"
                        ]
                      }
                    }
                  },
                  "transport": {
                    "protocol": "http",
                    "keep_alive": {
                      "enabled": true
                    }
                  },
                  "upstreams": [
                    {
                      "dial": "localhost:8881"
                    }
                  ]
                }
              ],
              "terminal": true
            }
          ],
          "tls_connection_policies": [],
          "automatic_https": {
            "disable": true
          },
          "logs": {
            "default_logger_name": "default"
          }
        }
      }
    }
  }
}
	`, "json")

	// Connect to the server
	conn, err := net.Dial("tcp", "localhost:8880")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()
	fmt.Println("Connected to server")

	// Send the HTTP headers
	request := "PUT /test.m3u8 HTTP/1.1\r\n" +
		"Host: uwsgi\r\n" +
		"X-Server-Name: wusgi\r\n" +
		"Connection: close\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		fmt.Println("Error sending request headers:", err)
		return
	}
	fmt.Println("Request headers sent")

	// Send data in chunks
	chunkSize := 100
	for i := 0; i < 5; i++ {
		// Write the chunk size in hexadecimal
		chunkSizeStr := strconv.FormatInt(int64(chunkSize), 16) + "\r\n"
		_, err = conn.Write([]byte(chunkSizeStr))
		if err != nil {
			fmt.Println("Error sending chunk size:", err)
			return
		}

		// Write the chunk data
		data := strings.Repeat("\x00", chunkSize) + "\r\n"
		_, err = conn.Write([]byte(data))
		if err != nil {
			fmt.Println("Error sending chunk data:", err)
			return
		}
	}

	// Signal the end of the chunked data
	_, err = conn.Write([]byte("0\r\n\r\n"))
	if err != nil {
		fmt.Println("Error sending final chunk:", err)
		return
	}

	// Close the connection
	fmt.Println("Connection closed")
}
