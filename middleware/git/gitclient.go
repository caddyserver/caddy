package git

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DefaultInterval is the minimum interval to delay before
// requesting another git pull
const DefaultInterval time.Duration = time.Hour * 1

// gitBinary holds the absolute path to git executable
var gitBinary string

// initMutex prevents parallel attempt to validate
// git availability in PATH
var initMutex sync.Mutex = sync.Mutex{}

// Repo is the structure that holds required information
// of a git repository.
type Repo struct {
	Url      string        // Repository URL
	Path     string        // Directory to pull to
	Host     string        // Git domain host e.g. github.com
	Branch   string        // Git branch
	KeyPath  string        // Path to private ssh key
	Interval time.Duration // Interval between pulls
	pulled   bool          // true if there is a successful pull
	lastPull time.Time     // time of the last successful pull
	sync.Mutex
}

// Pull requests a repository pull.
// If it has been performed previously, it returns
// and requests another pull in background.
// Otherwise it waits until the pull is done.
func (r *Repo) Pull() error {
	// if site is not pulled, pull
	if !r.pulled {
		return pull(r)
	}

	// request pull in background
	go pull(r)
	return nil
}

// pull performs git clone, or git pull if repository exists
func pull(r *Repo) error {
	r.Lock()
	defer r.Unlock()
	// if it is less than interval since last pull, return
	if time.Since(r.lastPull) <= r.Interval {
		return nil
	}

	params := []string{"clone", "-b", r.Branch, r.Url, r.Path}
	if r.pulled {
		params = []string{"pull", "origin", r.Branch}
	}

	// if key is specified, pull using ssh key
	if r.KeyPath != "" {
		return pullWithKey(r, params)
	}

	cmd := exec.Command(gitBinary, params...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if r.pulled {
		cmd.Dir = r.Path
	}

	var err error
	if err = cmd.Start(); err != nil {
		return err
	}

	if err = cmd.Wait(); err == nil {
		r.pulled = true
		r.lastPull = time.Now()
		log.Printf("%v pulled.\n", r.Url)
	}

	return err
}

// pullWithKey performs git clone or git pull if repository exists.
// It is used for private repositories and requires an ssh key.
// Note: currently only limited to Linux and OSX.
func pullWithKey(r *Repo, params []string) error {
	var gitSsh, script *os.File
	// ensure temporary files deleted after usage
	defer func() {
		if gitSsh != nil {
			os.Remove(gitSsh.Name())
		}
		if script != nil {
			os.Remove(script.Name())
		}
	}()

	var err error
	// write git.sh script to temp file
	gitSsh, err = writeScriptFile(gitWrapperScript(gitBinary))
	if err != nil {
		return err
	}

	// write git clone bash script to file
	script, err = writeScriptFile(bashScript(gitSsh.Name(), r, params))
	if err != nil {
		return err
	}

	// execute the git clone bash script
	cmd := exec.Command(script.Name())
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if r.pulled {
		cmd.Dir = r.Path
	}

	if err = cmd.Start(); err != nil {
		return err
	}

	if err = cmd.Wait(); err == nil {
		r.pulled = true
		r.lastPull = time.Now()
		log.Printf("%v pulled.\n", r.Url)
	}
	return err
}

// prepare prepares for a git pull
// and validates the configured directory
func prepare(r *Repo) error {
	// check if directory exists or is empty
	// if not, create directory
	fs, err := ioutil.ReadDir(r.Path)
	if err != nil || len(fs) == 0 {
		return os.MkdirAll(r.Path, os.FileMode(0755))
	}

	// validate git repo
	isGit := false
	for _, f := range fs {
		if f.IsDir() && f.Name() == ".git" {
			isGit = true
			break
		}
	}

	if isGit {
		// check if same repository
		var repoUrl string
		if repoUrl, err = getRepoUrl(r.Path); err == nil && repoUrl == r.Url {
			r.pulled = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("Cannot retrieve repo url for %v Error: %v", r.Path, err)
		}
		return fmt.Errorf("Another git repo '%v' exists at %v", repoUrl, r.Path)
	}
	return fmt.Errorf("Cannot git clone into %v, directory not empty.", r.Path)
}

// getRepoUrl retrieves remote origin url for the git repository at path
func getRepoUrl(path string) (string, error) {
	args := []string{"config", "--get", "remote.origin.url"}

	_, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	cmd := exec.Command(gitBinary, args...)
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// initGit validates git installation and locates the git executable
// binary in PATH
func initGit() error {
	// prevent concurrent call
	initMutex.Lock()
	defer initMutex.Unlock()

	// if validation has been done before and binary located in
	// PATH, return.
	if gitBinary != "" {
		return nil
	}

	// locate git binary in path
	var err error
	gitBinary, err = exec.LookPath("git")
	return err

}

// writeScriptFile writes content to a temporary file.
// It changes the temporary file mode to executable and
// closes it to prepare it for execution.
func writeScriptFile(content []byte) (file *os.File, err error) {
	if file, err = ioutil.TempFile("", "caddy"); err != nil {
		return nil, err
	}
	if _, err = file.Write(content); err != nil {
		return nil, err
	}
	if err = file.Chmod(os.FileMode(0755)); err != nil {
		return nil, err
	}
	return file, file.Close()
}

// gitWrapperScript forms content for git.sh script
var gitWrapperScript = func(gitBinary string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/bash

# The MIT License (MIT)
# Copyright (c) 2013 Alvin Abad

if [ $# -eq 0 ]; then
    echo "Git wrapper script that can specify an ssh-key file
Usage:
    git.sh -i ssh-key-file git-command
    "
    exit 1
fi

# remove temporary file on exit
trap 'rm -f /tmp/.git_ssh.$$' 0

if [ "$1" = "-i" ]; then
    SSH_KEY=$2; shift; shift
    echo "ssh -i $SSH_KEY \$@" > /tmp/.git_ssh.$$
    chmod +x /tmp/.git_ssh.$$
    export GIT_SSH=/tmp/.git_ssh.$$
fi

# in case the git command is repeated
[ "$1" = "git" ] && shift

# Run the git command
%v "$@"

`, gitBinary))
}

// bashScript forms content of bash script to clone or update a repo using ssh
var bashScript = func(gitShPath string, repo *Repo, params []string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/bash

mkdir -p ~/.ssh;
touch ~/.ssh/known_hosts;
ssh-keyscan -t rsa,dsa %v 2>&1 | sort -u - ~/.ssh/known_hosts > ~/.ssh/tmp_hosts;
cat ~/.ssh/tmp_hosts >> ~/.ssh/known_hosts;
%v -i %v %v;
`, repo.Host, gitShPath, repo.KeyPath, strings.Join(params, " ")))
}
