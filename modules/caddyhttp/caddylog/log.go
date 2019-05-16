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
		New:  func() (interface{}, error) { return new(Log), nil },
	})
}

// Log implements a simple logging middleware.
type Log struct {
	Filename string
	counter  int
}

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()

	// TODO: An example of returning errors
	// return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("this is a basic error"))
	// return caddyhttp.Error(http.StatusBadGateway, caddyhttp.HandlerError{
	// 	Err:     fmt.Errorf("this is a detailed error"),
	// 	Message: "We had trouble doing the thing.",
	// 	Recommendations: []string{
	// 		"Try reconnecting the gizbop.",
	// 		"Turn off the Internet.",
	// 	},
	// })

	if err := next.ServeHTTP(w, r); err != nil {
		return err
	}

	log.Println("latency:", time.Now().Sub(start), l.counter)

	return nil
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Log)(nil)
