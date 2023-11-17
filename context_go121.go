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

//go:build go1.21

package caddy

import (
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

// Slogger returns a slog logger that is intended for use by
// the most recent module associated with the context.
func (ctx Context) Slogger() *slog.Logger {
	if ctx.cfg == nil {
		// often the case in tests; just use a dev logger
		l, err := zap.NewDevelopment()
		if err != nil {
			panic("config missing, unable to create dev logger: " + err.Error())
		}
		return slog.New(zapslog.NewHandler(l.Core(), nil))
	}
	mod := ctx.Module()
	if mod == nil {
		return slog.New(zapslog.NewHandler(Log().Core(), nil))
	}

	return slog.New(zapslog.NewHandler(
		ctx.cfg.Logging.Logger(mod).Core(),
		&zapslog.HandlerOptions{
			LoggerName: string(mod.CaddyModule().ID),
		},
	))
}
