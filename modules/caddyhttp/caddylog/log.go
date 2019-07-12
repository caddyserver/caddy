// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddylog

import (
	"log"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.log",
		New:  func() interface{} { return new(Log) },
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
