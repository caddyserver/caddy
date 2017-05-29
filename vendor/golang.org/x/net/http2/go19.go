// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.9

package http2

import (
	"net/http"
)

func configureServer19(s *http.Server, conf *Server) error {
	s.RegisterOnShutdown(conf.state.startGracefulShutdown)
	return nil
}
