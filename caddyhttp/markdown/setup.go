// Copyright 2015 Light Code Labs, LLC
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

package markdown

import (
	"net/http"
	"path/filepath"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/russross/blackfriday"
)

func init() {
	caddy.RegisterPlugin("markdown", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Markdown middleware instance.
func setup(c *caddy.Controller) error {
	mdconfigs, err := markdownParse(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)

	md := Markdown{
		Root:    cfg.Root,
		FileSys: http.Dir(cfg.Root),
		Configs: mdconfigs,
	}

	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		md.Next = next
		return md
	})

	return nil
}

func markdownParse(c *caddy.Controller) ([]*Config, error) {
	var mdconfigs []*Config

	for c.Next() {
		md := &Config{
			Renderer:      blackfriday.HtmlRenderer(0, "", ""),
			Extensions:    make(map[string]struct{}),
			Template:      GetDefaultTemplate(),
			IndexFiles:    []string{},
			TemplateFiles: make(map[string]*cachedFileInfo),
		}

		// Get the path scope
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			md.PathScope = "/"
		case 1:
			md.PathScope = args[0]
		default:
			return mdconfigs, c.ArgErr()
		}

		// Load any other configuration parameters
		for c.NextBlock() {
			if err := loadParams(c, md); err != nil {
				return mdconfigs, err
			}
		}

		// If no extensions were specified, assume some defaults
		if len(md.Extensions) == 0 {
			md.Extensions[".md"] = struct{}{}
			md.Extensions[".markdown"] = struct{}{}
			md.Extensions[".mdown"] = struct{}{}
		}

		// Make a list of index files to match extensions
		for ext := range md.Extensions {
			md.IndexFiles = append(md.IndexFiles, "index"+ext)
		}
		mdconfigs = append(mdconfigs, md)
	}

	return mdconfigs, nil
}

func loadParams(c *caddy.Controller, mdc *Config) error {
	cfg := httpserver.GetConfig(c)

	switch c.Val() {
	case "ext":
		for _, ext := range c.RemainingArgs() {
			mdc.Extensions[ext] = struct{}{}
		}
		return nil
	case "css":
		if !c.NextArg() {
			return c.ArgErr()
		}
		mdc.Styles = append(mdc.Styles, c.Val())
		return nil
	case "js":
		if !c.NextArg() {
			return c.ArgErr()
		}
		mdc.Scripts = append(mdc.Scripts, c.Val())
		return nil
	case "template":
		tArgs := c.RemainingArgs()
		switch len(tArgs) {
		default:
			return c.ArgErr()
		case 1:
			fpath := filepath.ToSlash(filepath.Clean(cfg.Root + string(filepath.Separator) + tArgs[0]))

			if err := SetTemplate(mdc.Template, "", fpath); err != nil {
				return c.Errf("default template parse error: %v", err)
			}

			mdc.TemplateFiles[""] = &cachedFileInfo{
				path: fpath,
			}
			return nil
		case 2:
			fpath := filepath.ToSlash(filepath.Clean(cfg.Root + string(filepath.Separator) + tArgs[1]))

			if err := SetTemplate(mdc.Template, tArgs[0], fpath); err != nil {
				return c.Errf("template parse error: %v", err)
			}

			mdc.TemplateFiles[tArgs[0]] = &cachedFileInfo{
				path: fpath,
			}
			return nil
		}
	case "templatedir":
		if !c.NextArg() {
			return c.ArgErr()
		}

		pattern := c.Val()
		_, err := mdc.Template.ParseGlob(pattern)
		if err != nil {
			return c.Errf("template load error: %v", err)
		}
		if c.NextArg() {
			return c.ArgErr()
		}

		paths, err := filepath.Glob(pattern)
		if err != nil {
			return c.Errf("glob %q failed: %v", pattern, err)
		}
		for _, path := range paths {
			mdc.TemplateFiles[filepath.Base(path)] = &cachedFileInfo{
				path: path,
			}
		}
		return nil
	default:
		return c.Err("Expected valid markdown configuration property")
	}
}
