package git

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/middleware"
)

// Logger is used to log errors; if nil, the default log.Logger is used.
var Logger *log.Logger

// New creates a new instance of git middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	repo, err := parse(c)
	if err != nil {
		return nil, err
	}

	c.Startup(func() error {
		// Startup functions are blocking; start
		// service routine in background
		go func() {
			for {
				time.Sleep(repo.Interval)

				err := repo.Pull()
				if err != nil {
					if Logger == nil {
						log.Println(err)
					} else {
						Logger.Println(err)
					}
				}
			}
		}()

		// Do a pull right away to return error
		return repo.Pull()
	})

	return nil, err
}

func parse(c middleware.Controller) (*Repo, error) {
	repo := &Repo{Branch: "master", Interval: DefaultInterval, Path: c.Root()}

	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			repo.Path = filepath.Clean(c.Root() + string(filepath.Separator) + args[1])
			fallthrough
		case 1:
			repo.Url = args[0]
		}

		for c.NextBlock() {
			switch c.Val() {
			case "repo":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				repo.Url = c.Val()
			case "path":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				repo.Path = filepath.Clean(c.Root() + string(filepath.Separator) + c.Val())
			case "branch":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				repo.Branch = c.Val()
			case "key":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				repo.KeyPath = c.Val()
			case "interval":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				t, _ := strconv.Atoi(c.Val())
				if t > 0 {
					repo.Interval = time.Duration(t) * time.Second
				}
			case "then":
				thenArgs := c.RemainingArgs()
				if len(thenArgs) == 0 {
					return nil, c.ArgErr()
				}
				repo.Then = strings.Join(thenArgs, " ")
			}
		}
	}

	// if repo is not specified, return error
	if repo.Url == "" {
		return nil, c.ArgErr()
	}

	// if private key is not specified, convert repository url to https
	// to avoid ssh authentication
	// else validate git url
	// Note: private key support not yet available on Windows
	var err error
	if repo.KeyPath == "" {
		repo.Url, repo.Host, err = sanitizeHttp(repo.Url)
	} else {
		repo.Url, repo.Host, err = sanitizeGit(repo.Url)
		// TODO add Windows support for private repos
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("Private repository not yet supported on Windows")
		}
	}

	if err != nil {
		return nil, err
	}

	// validate git availability in PATH
	if err = initGit(); err != nil {
		return nil, err
	}

	return repo, repo.prepare()
}

// sanitizeHttp cleans up repository url and converts to https format
// if currently in ssh format.
// Returns sanitized url, hostName (e.g. github.com, bitbucket.com)
// and possible error
func sanitizeHttp(repoUrl string) (string, string, error) {
	url, err := url.Parse(repoUrl)
	if err != nil {
		return "", "", err
	}

	if url.Host == "" && strings.HasPrefix(url.Path, "git@") {
		url.Path = url.Path[len("git@"):]
		i := strings.Index(url.Path, ":")
		if i < 0 {
			return "", "", fmt.Errorf("Invalid git url %s", repoUrl)
		}
		url.Host = url.Path[:i]
		url.Path = "/" + url.Path[i+1:]
	}

	repoUrl = "https://" + url.Host + url.Path
	return repoUrl, url.Host, nil
}

// sanitizeGit cleans up repository url and validate ssh format.
// Returns sanitized url, hostName (e.g. github.com, bitbucket.com)
// and possible error
func sanitizeGit(repoUrl string) (string, string, error) {
	repoUrl = strings.TrimSpace(repoUrl)
	if !strings.HasPrefix(repoUrl, "git@") || strings.Index(repoUrl, ":") < len("git@a:") {
		return "", "", fmt.Errorf("Invalid git url %s", repoUrl)
	}
	hostUrl := repoUrl[len("git@"):]
	i := strings.Index(hostUrl, ":")
	host := hostUrl[:i]
	return repoUrl, host, nil
}

// logger is an helper function to retrieve the available logger
func logger() *log.Logger {
	if Logger == nil {
		Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	return Logger
}
