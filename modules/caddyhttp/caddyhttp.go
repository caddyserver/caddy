package caddyhttp

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/lightcodelabs/caddy2"
)

func init() {
	err := caddy2.RegisterModule(caddy2.Module{
		Name: "http",
		New:  func() (interface{}, error) { return new(httpModuleConfig), nil },
	})
	if err != nil {
		log.Fatal(err)
	}
}

type httpModuleConfig struct {
	Servers map[string]httpServerConfig `json:"servers"`

	servers []*http.Server
}

func (hc *httpModuleConfig) Run() error {
	// fmt.Printf("RUNNING: %#v\n", hc)

	for _, srv := range hc.Servers {
		s := &http.Server{
			ReadTimeout:       time.Duration(srv.ReadTimeout),
			ReadHeaderTimeout: time.Duration(srv.ReadHeaderTimeout),
		}

		for _, lnAddr := range srv.Listen {
			proto, addrs, err := parseListenAddr(lnAddr)
			if err != nil {
				return fmt.Errorf("parsing listen address '%s': %v", lnAddr, err)
			}
			for _, addr := range addrs {
				ln, err := caddy2.Listen(proto, addr)
				if err != nil {
					return fmt.Errorf("%s: listening on %s: %v", proto, addr, err)
				}
				go s.Serve(ln)
				hc.servers = append(hc.servers, s)
			}
		}
	}

	return nil
}

func (hc *httpModuleConfig) Cancel() error {
	for _, s := range hc.servers {
		err := s.Shutdown(context.Background()) // TODO
		if err != nil {
			return err
		}
	}
	return nil
}

func parseListenAddr(a string) (proto string, addrs []string, err error) {
	proto = "tcp"
	if idx := strings.Index(a, "/"); idx >= 0 {
		proto = strings.ToLower(strings.TrimSpace(a[:idx]))
		a = a[idx+1:]
	}
	var host, port string
	host, port, err = net.SplitHostPort(a)
	if err != nil {
		return
	}
	ports := strings.SplitN(port, "-", 2)
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}
	var start, end int
	start, err = strconv.Atoi(ports[0])
	if err != nil {
		return
	}
	end, err = strconv.Atoi(ports[1])
	if err != nil {
		return
	}
	if end < start {
		err = fmt.Errorf("end port must be greater than start port")
		return
	}
	for p := start; p <= end; p++ {
		addrs = append(addrs, net.JoinHostPort(host, fmt.Sprintf("%d", p)))
	}
	return
}

type httpServerConfig struct {
	Listen            []string        `json:"listen"`
	ReadTimeout       caddy2.Duration `json:"read_timeout"`
	ReadHeaderTimeout caddy2.Duration `json:"read_header_timeout"`
}
