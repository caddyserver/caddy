package git

import (
	"fmt"
	"github.com/mholt/caddy/middleware"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Git represents a middleware instance that pulls git repository.
type Git struct {
	Next middleware.Handler
	Repo *Repo
}

// ServeHTTP satisfies the middleware.Handler interface.
func (g Git) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if err := g.Repo.Pull(); err != nil {
		return 500, err
	}
	return g.Next.ServeHTTP(w, r)
}

// New creates a new instance of git middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	repo, err := parse(c)
	if err != nil {
		return nil, err
	}
	err = repo.Pull()
	return func(next middleware.Handler) middleware.Handler {
		return Git{Next: next, Repo: repo}
	}, err
}

func parse(c middleware.Controller) (*Repo, error) {
	repo := &Repo{Branch: "master", Interval: DefaultInterval, Path: c.Root()}

	for c.Next() {
		args := c.RemainingArgs()

		switch len(args) {
		case 2:
			repo.Path = filepath.Join(c.Root(), args[1])
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
				repo.Path = filepath.Join(c.Root(), c.Val())
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

	return repo, prepare(repo)
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
