package git

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/git/gitos"
)

// DefaultInterval is the minimum interval to delay before
// requesting another git pull
const DefaultInterval time.Duration = time.Hour * 1

// Number of retries if git pull fails
const numRetries = 3

// gitBinary holds the absolute path to git executable
var gitBinary string

// shell holds the shell to be used. Either sh or bash.
var shell string

// initMutex prevents parallel attempt to validate
// git requirements.
var initMutex = sync.Mutex{}

// Services holds all git pulling services and provides the function to
// stop them.
var Services = &services{}

// Repo is the structure that holds required information
// of a git repository.
type Repo struct {
	URL        string        // Repository URL
	Path       string        // Directory to pull to
	Host       string        // Git domain host e.g. github.com
	Branch     string        // Git branch
	KeyPath    string        // Path to private ssh key
	Interval   time.Duration // Interval between pulls
	Then       string        // Command to execute after successful git pull
	pulled     bool          // true if there was a successful pull
	lastPull   time.Time     // time of the last successful pull
	lastCommit string        // hash for the most recent commit
	sync.Mutex
	HookUrl    string // url to listen on for webhooks
	HookSecret string // secret to validate hooks

}

// Pull attempts a git clone.
// It retries at most numRetries times if error occurs
func (r *Repo) Pull() error {
	r.Lock()
	defer r.Unlock()

	// prevent a pull if the last one was less than 5 seconds ago
	if gos.TimeSince(r.lastPull) < 5*time.Second {
		return nil
	}

	// keep last commit hash for comparison later
	lastCommit := r.lastCommit

	var err error
	// Attempt to pull at most numRetries times
	for i := 0; i < numRetries; i++ {
		if err = r.pull(); err == nil {
			break
		}
		Logger().Println(err)
	}

	if err != nil {
		return err
	}

	// check if there are new changes,
	// then execute post pull command
	if r.lastCommit == lastCommit {
		Logger().Println("No new changes.")
		return nil
	}
	return r.postPullCommand()
}

// Pull performs git clone, or git pull if repository exists
func (r *Repo) pull() error {
	params := []string{"clone", "-b", r.Branch, r.URL, r.Path}
	if r.pulled {
		params = []string{"pull", "origin", r.Branch}
	}

	// if key is specified, pull using ssh key
	if r.KeyPath != "" {
		return r.pullWithKey(params)
	}

	dir := ""
	if r.pulled {
		dir = r.Path
	}

	var err error
	if err = runCmd(gitBinary, params, dir); err == nil {
		r.pulled = true
		r.lastPull = time.Now()
		Logger().Printf("%v pulled.\n", r.URL)
		r.lastCommit, err = r.getMostRecentCommit()
	}
	return err
}

// pullWithKey is used for private repositories and requires an ssh key.
// Note: currently only limited to Linux and OSX.
func (r *Repo) pullWithKey(params []string) error {
	var gitSSH, script gitos.File
	// ensure temporary files deleted after usage
	defer func() {
		if gitSSH != nil {
			gos.Remove(gitSSH.Name())
		}
		if script != nil {
			gos.Remove(script.Name())
		}
	}()

	var err error
	// write git.sh script to temp file
	gitSSH, err = writeScriptFile(gitWrapperScript())
	if err != nil {
		return err
	}

	// write git clone bash script to file
	script, err = writeScriptFile(bashScript(gitSSH.Name(), r, params))
	if err != nil {
		return err
	}

	dir := ""
	if r.pulled {
		dir = r.Path
	}

	if err = runCmd(script.Name(), nil, dir); err == nil {
		r.pulled = true
		r.lastPull = time.Now()
		Logger().Printf("%v pulled.\n", r.URL)
		r.lastCommit, err = r.getMostRecentCommit()
	}
	return err
}

// Prepare prepares for a git pull
// and validates the configured directory
func (r *Repo) Prepare() error {
	// check if directory exists or is empty
	// if not, create directory
	fs, err := gos.ReadDir(r.Path)
	if err != nil || len(fs) == 0 {
		return gos.MkdirAll(r.Path, os.FileMode(0755))
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
		var repoURL string
		if repoURL, err = r.getRepoURL(); err == nil {
			// add .git suffix if missing for adequate comparison.
			if !strings.HasSuffix(repoURL, ".git") {
				repoURL += ".git"
			}
			if repoURL == r.URL {
				r.pulled = true
				return nil
			}
		}
		if err != nil {
			return fmt.Errorf("Cannot retrieve repo url for %v Error: %v", r.Path, err)
		}
		return fmt.Errorf("Another git repo '%v' exists at %v", repoURL, r.Path)
	}
	return fmt.Errorf("Cannot git clone into %v, directory not empty.", r.Path)
}

// getMostRecentCommit gets the hash of the most recent commit to the
// repository. Useful for checking if changes occur.
func (r *Repo) getMostRecentCommit() (string, error) {
	command := gitBinary + ` --no-pager log -n 1 --pretty=format:"%H"`
	c, args, err := middleware.SplitCommandAndArgs(command)
	if err != nil {
		return "", err
	}
	return runCmdOutput(c, args, r.Path)
}

// getRepoURL retrieves remote origin url for the git repository at path
func (r *Repo) getRepoURL() (string, error) {
	_, err := gos.Stat(r.Path)
	if err != nil {
		return "", err
	}
	args := []string{"config", "--get", "remote.origin.url"}
	return runCmdOutput(gitBinary, args, r.Path)
}

// postPullCommand executes r.Then.
// It is trigged after successful git pull
func (r *Repo) postPullCommand() error {
	if r.Then == "" {
		return nil
	}
	c, args, err := middleware.SplitCommandAndArgs(r.Then)
	if err != nil {
		return err
	}

	if err = runCmd(c, args, r.Path); err == nil {
		Logger().Printf("Command %v successful.\n", r.Then)
	}
	return err
}

// Init validates git installation, locates the git executable
// binary in PATH and check for available shell to use.
func Init() error {
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
	if gitBinary, err = gos.LookPath("git"); err != nil {
		return fmt.Errorf("Git middleware requires git installed. Cannot find git binary in PATH")
	}

	// locate bash in PATH. If not found, fallback to sh.
	// If neither is found, return error.
	shell = "bash"
	if _, err = gos.LookPath("bash"); err != nil {
		shell = "sh"
		if _, err = gos.LookPath("sh"); err != nil {
			return fmt.Errorf("Git middleware requires either bash or sh.")
		}
	}
	return nil
}

// runCmd is a helper function to run commands.
// It runs command with args from directory at dir.
// The executed process outputs to os.Stderr
func runCmd(command string, args []string, dir string) error {
	cmd := gos.Command(command, args...)
	cmd.Stdout(os.Stderr)
	cmd.Stderr(os.Stderr)
	cmd.Dir(dir)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

// runCmdOutput is a helper function to run commands and return output.
// It runs command with args from directory at dir.
// If successful, returns output and nil error
func runCmdOutput(command string, args []string, dir string) (string, error) {
	cmd := gos.Command(command, args...)
	cmd.Dir(dir)
	var err error
	if output, err := cmd.Output(); err == nil {
		return string(bytes.TrimSpace(output)), nil
	}
	return "", err
}

// writeScriptFile writes content to a temporary file.
// It changes the temporary file mode to executable and
// closes it to prepare it for execution.
func writeScriptFile(content []byte) (file gitos.File, err error) {
	if file, err = gos.TempFile("", "caddy"); err != nil {
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
func gitWrapperScript() []byte {
	return []byte(fmt.Sprintf(`#!/bin/%v

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

`, shell, gitBinary))
}

// bashScript forms content of bash script to clone or update a repo using ssh
func bashScript(gitShPath string, repo *Repo, params []string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/%v

mkdir -p ~/.ssh;
touch ~/.ssh/known_hosts;
ssh-keyscan -t rsa,dsa %v 2>&1 | sort -u - ~/.ssh/known_hosts > ~/.ssh/tmp_hosts;
cat ~/.ssh/tmp_hosts >> ~/.ssh/known_hosts;
%v -i %v %v;
`, shell, repo.Host, gitShPath, repo.KeyPath, strings.Join(params, " ")))
}
