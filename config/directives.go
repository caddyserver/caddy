package config

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

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
		"cpu": func(p *parser) error {
			sysCores := runtime.NumCPU()

			if !p.nextArg() {
				return p.argErr()
			}
			strNum := p.tkn()

			setCPU := func(val int) {
				if val < 1 {
					val = 1
				}
				if val > sysCores {
					val = sysCores
				}
				if val > p.cfg.MaxCPU {
					p.cfg.MaxCPU = val
				}
			}

			if strings.HasSuffix(strNum, "%") {
				// Percent
				var percent float32
				pctStr := strNum[:len(strNum)-1]
				pctInt, err := strconv.Atoi(pctStr)
				if err != nil || pctInt < 1 || pctInt > 100 {
					return p.err("Parse", "Invalid number '"+strNum+"' (must be a positive percentage between 1 and 100)")
				}
				percent = float32(pctInt) / 100
				setCPU(int(float32(sysCores) * percent))
			} else {
				// Number
				num, err := strconv.Atoi(strNum)
				if err != nil || num < 0 {
					return p.err("Parse", "Invalid number '"+strNum+"' (requires positive integer or percent)")
				}
				setCPU(num)
			}
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
