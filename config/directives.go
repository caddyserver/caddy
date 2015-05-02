package config

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/mholt/caddy/middleware"
)

// dirFunc is a type of parsing function which processes
// a particular directive and populates the config.
type dirFunc func(*parser) error

// validDirectives is a map of valid, built-in directive names
// to their parsing function. Built-in directives cannot be
// ordered, so they should only be used for internal server
// configuration; not directly handling requests.
var validDirectives map[string]dirFunc

func init() {
	// This has to be in the init function
	// to avoid an initialization loop error because
	// the 'import' directive (key) in this map
	// invokes a method that uses this map.
	validDirectives = map[string]dirFunc{
		"root": func(p *parser) error {
			if !p.nextArg() {
				return p.argErr()
			}
			p.cfg.Root = p.tkn()

			// Ensure root folder exists
			_, err := os.Stat(p.cfg.Root)
			if err != nil {
				if os.IsNotExist(err) {
					// Allow this, because the folder might appear later.
					// But make sure the user knows!
					log.Printf("Warning: Root path %s does not exist", p.cfg.Root)
				} else {
					return p.err("Path", fmt.Sprintf("Unable to access root path '%s': %s", p.cfg.Root, err.Error()))
				}
			}
			return nil
		},
		"import": func(p *parser) error {
			if !p.nextArg() {
				return p.argErr()
			}

			filename := p.tkn()
			file, err := os.Open(filename)
			if err != nil {
				return p.err("Parse", err.Error())
			}
			defer file.Close()
			p2, err := newParser(file)
			if err != nil {
				return p.err("Parse", "Could not import "+filename+"; "+err.Error())
			}

			p2.cfg = p.cfg
			err = p2.directives()
			if err != nil {
				return err
			}
			p.cfg = p2.cfg

			return nil
		},
		"tls": func(p *parser) error {
			tls := TLSConfig{Enabled: true}

			if !p.nextArg() {
				return p.argErr()
			}
			tls.Certificate = p.tkn()

			if !p.nextArg() {
				return p.argErr()
			}
			tls.Key = p.tkn()

			p.cfg.TLS = tls
			return nil
		},
		"startup": func(p *parser) error {
			// TODO: This code is duplicated with the shutdown directive below

			if !p.nextArg() {
				return p.argErr()
			}

			command, args, err := middleware.SplitCommandAndArgs(p.tkn())
			if err != nil {
				return p.err("Parse", err.Error())
			}

			startupfn := func() error {
				cmd := exec.Command(command, args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					return err
				}
				return nil
			}

			p.cfg.Startup = append(p.cfg.Startup, startupfn)
			return nil
		},
		"shutdown": func(p *parser) error {
			if !p.nextArg() {
				return p.argErr()
			}

			command, args, err := middleware.SplitCommandAndArgs(p.tkn())
			if err != nil {
				return p.err("Parse", err.Error())
			}

			shutdownfn := func() error {
				cmd := exec.Command(command, args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					return err
				}
				return nil
			}

			p.cfg.Shutdown = append(p.cfg.Shutdown, shutdownfn)
			return nil
		},
	}
}
