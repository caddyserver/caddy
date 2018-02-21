package builds

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MakeLdFlags makes a string to pass in as ldflags when building Caddy.
// This automates proper versioning, so it uses git to get information
// about the current version of Caddy.
func MakeLdFlags(repoPath string) (string, error) {
	run := func(cmd *exec.Cmd, ignoreError bool) (string, error) {
		cmd.Dir = repoPath
		out, err := cmd.Output()
		if err != nil && !ignoreError {
			return string(out), err
		}
		return strings.TrimSpace(string(out)), nil
	}

	var ldflags []string
	var includeBuildDate bool

	for _, ldvar := range []struct {
		name  string
		value func() (string, error)
	}{
		// Current tag, if HEAD is on a tag
		{
			name: "gitTag",
			value: func() (string, error) {
				// OK to ignore error since HEAD may not be at a tag
				return run(exec.Command("git", "describe", "--exact-match", "HEAD"), true)
			},
		},

		// Nearest tag on branch
		{
			name: "gitNearestTag",
			value: func() (string, error) {
				return run(exec.Command("git", "describe", "--abbrev=0", "--tags", "HEAD"), false)
			},
		},

		// Commit SHA
		{
			name: "gitCommit",
			value: func() (string, error) {
				return run(exec.Command("git", "rev-parse", "--short", "HEAD"), false)
			},
		},

		// Summary of uncommitted changes
		{
			name: "gitShortStat",
			value: func() (string, error) {
				return run(exec.Command("git", "diff-index", "--shortstat", "HEAD"), false)
			},
		},

		// List of modified files
		{
			name: "gitFilesModified",
			value: func() (string, error) {
				return run(exec.Command("git", "diff-index", "--name-only", "HEAD"), false)
			},
		},

		// Timestamp of build -- MUST BE LAST since we only include build date if
		// certain conditions determined by other ldflags are met
		{
			name: "buildDate",
			value: func() (string, error) {
				return time.Now().UTC().Format("Mon Jan 02 15:04:05 MST 2006"), nil
			},
		},
	} {
		if ldvar.name == "buildDate" && !includeBuildDate {
			continue
		}

		value, err := ldvar.value()
		if err != nil {
			return "", err
		}

		// putting timestamp in the binary breaks byte-level reproducibility,
		// so only enable it if the build is not at a clean commit anyway
		if ldvar.name == "gitFilesModified" && value != "" {
			includeBuildDate = true
		}

		ldflags = append(ldflags, fmt.Sprintf(`-X "%s.%s=%s"`, ldFlagVarPkg, ldvar.name, value))
	}

	return strings.Join(ldflags, " "), nil
}

const ldFlagVarPkg = "github.com/mholt/caddy/caddy/caddymain"
