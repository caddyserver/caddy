package caddylog

import (
	"log"
	"net/http"
	"time"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.middleware.log",
		New:  func() (interface{}, error) { return &Log{}, nil },
	})
}

// Log implements a simple logging middleware.
type Log struct {
	Filename string
}

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()

	if err := next.ServeHTTP(w, r); err != nil {
		return err
	}

	log.Println("latency:", time.Now().Sub(start))

	return nil
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = &Log{}
