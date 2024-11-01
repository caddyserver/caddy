package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

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

	var fullFile = []byte(strings.Repeat("\x00", 500))

	done := make(chan struct{})
	// start the server
	server := testLowLatencyUpload(t, fullFile, done)
	go server.ListenAndServe()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Connect to the server
	conn, err := net.Dial("tcp", "localhost:8880")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
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
	conn.Close()
	// Close the connection
	fmt.Println("Connection closed")

	<-done
}

func testLowLatencyUpload(t *testing.T, testFileBytes []byte, done chan struct{}) *http.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request method is PUT
		if r.Method != http.MethodPut {
			http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
			return
		}

		fmt.Println("Received PUT request")

		// wait 1 second to simulate processing
		time.Sleep(1 * time.Second)

		// Create a context with a timeout
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second) // Set your desired timeout
		defer cancel()

		// Create a buffer to store the incoming data
		var buffer bytes.Buffer

		// Use a separate goroutine to perform the copy
		doneCopy := make(chan error)

		go func() {
			_, err := io.Copy(&buffer, r.Body)
			doneCopy <- err
		}()

		select {
		case err := <-doneCopy:
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to write data to buffer: %v", err), http.StatusInternalServerError)
				return
			}
			fmt.Println("Data written to buffer successfully")
		case <-ctx.Done():
		}

		// Verify the received data matches testFile
		if bytes.Equal(buffer.Bytes(), testFileBytes) {
			fmt.Println("Data received matches the expected content", buffer.Len(), len(testFileBytes))
		} else {
			t.Errorf("Data received does not match the expected content")
		}
		close(done)
	})

	server := &http.Server{
		Addr:    "localhost:8881",
		Handler: handler,
	}
	return server
}
