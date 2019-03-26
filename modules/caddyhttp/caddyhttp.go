package caddyhttp

import (
	"log"

	"bitbucket.org/lightcodelabs/caddy2"
)

func init() {
	err := caddy2.RegisterModule(caddy2.Module{
		Name: "http",
		New:  func() (interface{}, error) { return httpModuleConfig{}, nil },
	})
	if err != nil {
		log.Fatal(err)
	}
}

type httpModuleConfig struct {
	Servers map[string]httpServerConfig `json:"servers"`
}

type httpServerConfig struct {
	Listen            []string `json:"listen"`
	ReadTimeout       string   `json:"read_timeout"`
	ReadHeaderTimeout string   `json:"read_header_timeout"`
}
