package integration

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReverseProxyHealthCheck(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		http_port     9080
		https_port    9443
	}
	http://localhost:2020 {
		respond "Hello, World!"
	}
	http://localhost:2021 {
		respond "ok"
	}
	http://localhost:9080 {
		reverse_proxy {
			to localhost:2020
	
			health_path /health
			health_port 2021
			health_interval 2s
			health_timeout 5s
		}
	}
  `, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}

func TestReverseProxyHealthCheckUnixSocket(t *testing.T) {
	tester := caddytest.NewTester(t)
	f, err := ioutil.TempFile("", "*.sock")
	if err != nil {
		t.Errorf("failed to create TempFile: %s", err)
		return
	}
	// a hack to get a file name within a valid path to use as socket
	socketName := f.Name()
	os.Remove(f.Name())

	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/health") {
				w.Write([]byte("ok"))
				return
			}
			w.Write([]byte("Hello, World!"))
		}),
	}

	unixListener, err := net.Listen("unix", socketName)
	if err != nil {
		t.Errorf("failed to listen on the socket: %s", err)
		return
	}
	go server.Serve(unixListener)
	t.Cleanup(func() {
		server.Close()
	})
	runtime.Gosched() // Allow other goroutines to run

	tester.InitServer(fmt.Sprintf(`
	{
		http_port     9080
		https_port    9443
	}
	http://localhost:9080 {
		reverse_proxy {
			to unix/%s
	
			health_path /health
			health_port 2021
			health_interval 2s
			health_timeout 5s
		}
	}
  `, socketName), "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/", 200, "Hello, World!")
}
