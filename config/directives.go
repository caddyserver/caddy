package config

// dirFunc is a type of parsing function which processes
// a particular directive and populates the config.
type dirFunc func(*parser) error

// validDirectives is a map of valid directive names to
// their parsing function.
var validDirectives map[string]dirFunc

func init() {
	// This has to be in the init function
	// to avoid an initialization loop error because
	// the 'import' directive (key) in this map
	// invokes a method that uses this map.
	validDirectives = map[string]dirFunc{
		"root": func(p *parser) error {
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			p.cfg.Root = p.tkn()
			return nil
		},
		"import": func(p *parser) error {
			if !p.lexer.NextArg() {
				return p.argErr()
			}

			p2 := parser{}
			err := p2.lexer.Load(p.tkn())
			if err != nil {
				return p.err("Parse", err.Error())
			}
			defer p2.lexer.Close()

			p2.cfg = p.cfg
			err = p2.directives()
			if err != nil {
				return err
			}
			p.cfg = p2.cfg

			return nil
		},
		"gzip": func(p *parser) error {
			p.cfg.Gzip = true
			return nil
		},
		"log": func(p *parser) error {
			log := Log{Enabled: true}

			// Get the type of log (requests, errors, etc.)
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			logWhat := p.tkn()

			// Set the log output file
			if p.lexer.NextArg() {
				log.OutputFile = p.tkn()
			}

			// Set the log output format
			if p.lexer.NextArg() {
				log.Format = p.tkn()
			}

			switch logWhat {
			case "requests":
				if log.OutputFile == "" || log.OutputFile == "_" {
					log.OutputFile = DefaultRequestsLog
				}
				p.cfg.RequestLog = log
			case "errors":
				if log.OutputFile == "" || log.OutputFile == "_" {
					log.OutputFile = DefaultErrorsLog
				}
				p.cfg.ErrorLog = log
			default:
				return p.err("Parse", "Unknown log '"+logWhat+"'")
			}

			return nil
		},
		"rewrite": func(p *parser) error {
			var rw Rewrite

			if !p.lexer.NextArg() {
				return p.argErr()
			}
			rw.From = p.tkn()

			if !p.lexer.NextArg() {
				return p.argErr()
			}
			rw.To = p.tkn()

			p.cfg.Rewrites = append(p.cfg.Rewrites, rw)
			return nil
		},
		"redir": func(p *parser) error {
			var redir Redirect

			// From
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			redir.From = p.tkn()

			// To
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			redir.To = p.tkn()

			// Status Code
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			if code, ok := httpRedirs[p.tkn()]; !ok {
				return p.err("Parse", "Invalid redirect code '"+p.tkn()+"'")
			} else {
				redir.Code = code
			}

			p.cfg.Redirects = append(p.cfg.Redirects, redir)
			return nil
		},
		"ext": func(p *parser) error {
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			p.cfg.Extensions = append(p.cfg.Extensions, p.tkn())
			for p.lexer.NextArg() {
				p.cfg.Extensions = append(p.cfg.Extensions, p.tkn())
			}
			return nil
		},
		"error": func(p *parser) error {
			if !p.lexer.NextArg() {
				return p.argErr()
			}
			if code, ok := httpErrors[p.tkn()]; !ok {
				return p.err("Syntax", "Invalid error code '"+p.tkn()+"'")
			} else if val, exists := p.cfg.ErrorPages[code]; exists {
				return p.err("Config", p.tkn()+" error page already configured to be '"+val+"'")
			} else {
				if !p.lexer.NextArg() {
					return p.argErr()
				}
				p.cfg.ErrorPages[code] = p.tkn()
			}
			return nil
		},
		"header": func(p *parser) error {
			var head Headers
			var isNewPattern bool

			if !p.lexer.NextArg() {
				return p.argErr()
			}
			pattern := p.tkn()

			// See if we already have a definition for this URL pattern...
			for _, h := range p.cfg.Headers {
				if h.Url == pattern {
					head = h
					break
				}
			}

			// ...otherwise, this is a new pattern
			if head.Url == "" {
				head.Url = pattern
				isNewPattern = true
			}

			processHeaderBlock := func() error {
				err := p.openCurlyBrace()
				if err != nil {
					return err
				}
				for p.lexer.Next() {
					if p.tkn() == "}" {
						break
					}
					h := Header{Name: p.tkn()}
					if p.lexer.NextArg() {
						h.Value = p.tkn()
					}
					head.Headers = append(head.Headers, h)
				}
				err = p.closeCurlyBrace()
				if err != nil {
					return err
				}
				return nil
			}

			// A single header could be declared on the same line, or
			// multiple headers can be grouped by URL pattern, so we have
			// to look for both here.
			if p.lexer.NextArg() {
				if p.tkn() == "{" {
					err := processHeaderBlock()
					if err != nil {
						return err
					}
				} else {
					h := Header{Name: p.tkn()}
					if p.lexer.NextArg() {
						h.Value = p.tkn()
					}
					head.Headers = append(head.Headers, h)
				}
			} else {
				// Okay, it might be an opening curly brace on the next line
				if !p.lexer.Next() {
					return p.eofErr()
				}
				err := processHeaderBlock()
				if err != nil {
					return err
				}
			}

			if isNewPattern {
				p.cfg.Headers = append(p.cfg.Headers, head)
			} else {
				for i := 0; i < len(p.cfg.Headers); i++ {
					if p.cfg.Headers[i].Url == pattern {
						p.cfg.Headers[i] = head
						break
					}
				}
			}

			return nil
		},
		"tls": func(p *parser) error {
			tls := TLSConfig{Enabled: true}

			if !p.lexer.NextArg() {
				return p.argErr()
			}
			tls.Certificate = p.tkn()

			if !p.lexer.NextArg() {
				return p.argErr()
			}
			tls.Key = p.tkn()

			p.cfg.TLS = tls
			return nil
		},
	}
}
