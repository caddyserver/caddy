package gitos

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"time"
)

// File is an abstraction for file (os.File).
type File interface {
	// Name returns the name of the file
	Name() string

	// Stat returns the FileInfo structure describing file.
	Stat() (os.FileInfo, error)

	// Close closes the File, rendering it unusable for I/O.
	Close() error

	// Chmod changes the mode of the file.
	Chmod(os.FileMode) error

	// Read reads up to len(b) bytes from the File. It returns the number of
	// bytes read and an error, if any.
	Read([]byte) (int, error)

	// Write writes len(b) bytes to the File. It returns the number of bytes
	// written and an error, if any.
	Write([]byte) (int, error)
}

// Cmd is an abstraction for external commands (os.Cmd).
type Cmd interface {
	// Run starts the specified command and waits for it to complete.
	Run() error

	// Start starts the specified command but does not wait for it to complete.
	Start() error

	// Wait waits for the command to exit. It must have been started by Start.
	Wait() error

	// Output runs the command and returns its standard output.
	Output() ([]byte, error)

	// Dir sets the working directory of the command.
	Dir(string)

	// Stdin sets the process's standard input.
	Stdin(io.Reader)

	// Stdout sets the process's standard output.
	Stdout(io.Writer)

	// Stderr sets the process's standard output.
	Stderr(io.Writer)
}

// gitCmd represents external commands executed by git.
type gitCmd struct {
	*exec.Cmd
}

// Dir sets the working directory of the command.
func (g *gitCmd) Dir(dir string) {
	g.Cmd.Dir = dir
}

// Stdin sets the process's standard input.
func (g *gitCmd) Stdin(stdin io.Reader) {
	g.Cmd.Stdin = stdin
}

// Stdout sets the process's standard output.
func (g *gitCmd) Stdout(stdout io.Writer) {
	g.Cmd.Stdout = stdout
}

// Stderr sets the process's standard output.
func (g *gitCmd) Stderr(stderr io.Writer) {
	g.Cmd.Stderr = stderr
}

// OS is an abstraction for required OS level functions.
type OS interface {
	// Command returns the Cmd to execute the named program with the
	// given arguments.
	Command(string, ...string) Cmd

	// Mkdir creates a new directory with the specified name and permission
	// bits.
	Mkdir(string, os.FileMode) error

	// MkdirAll creates a directory named path, along with any necessary
	// parents.
	MkdirAll(string, os.FileMode) error

	// Stat returns a FileInfo describing the named file.
	Stat(string) (os.FileInfo, error)

	// Remove removes the named file or directory.
	Remove(string) error

	// ReadDir reads the directory named by dirname and returns a list of
	// directory entries.
	ReadDir(string) ([]os.FileInfo, error)

	// LookPath searches for an executable binary named file in the directories
	// named by the PATH environment variable.
	LookPath(string) (string, error)

	// TempFile creates a new temporary file in the directory dir with a name
	// beginning with prefix, opens the file for reading and writing, and
	// returns the resulting File.
	TempFile(string, string) (File, error)

	// Sleep pauses the current goroutine for at least the duration d. A
	// negative or zero duration causes Sleep to return immediately.
	Sleep(time.Duration)

	// NewTicker returns a new Ticker containing a channel that will send the
	// time with a period specified by the argument.
	NewTicker(time.Duration) Ticker

	// TimeSince returns the time elapsed since the argument.
	TimeSince(time.Time) time.Duration
}

// Ticker is an abstraction for Ticker (time.Ticker)
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// GitTicker is the implementation of Ticker for git.
type GitTicker struct {
	*time.Ticker
}

// C returns the channel on which the ticks are delivered.s
func (g *GitTicker) C() <-chan time.Time {
	return g.Ticker.C
}

// GitOS is the implementation of OS for git.
type GitOS struct{}

// Mkdir calls os.Mkdir.
func (g GitOS) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

// MkdirAll calls os.MkdirAll.
func (g GitOS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// Stat calls os.Stat.
func (g GitOS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Remove calls os.Remove.
func (g GitOS) Remove(name string) error {
	return os.Remove(name)
}

// LookPath calls exec.LookPath.
func (g GitOS) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// TempFile calls ioutil.TempFile.
func (g GitOS) TempFile(dir, prefix string) (File, error) {
	return ioutil.TempFile(dir, prefix)
}

// ReadDir calls ioutil.ReadDir.
func (g GitOS) ReadDir(dirname string) ([]os.FileInfo, error) {
	return ioutil.ReadDir(dirname)
}

// Command calls exec.Command.
func (g GitOS) Command(name string, args ...string) Cmd {
	return &gitCmd{exec.Command(name, args...)}
}

// Sleep calls time.Sleep.
func (g GitOS) Sleep(d time.Duration) {
	time.Sleep(d)
}

// New Ticker calls time.NewTicker.
func (g GitOS) NewTicker(d time.Duration) Ticker {
	return &GitTicker{time.NewTicker(d)}
}

// TimeSince calls time.Since
func (g GitOS) TimeSince(t time.Time) time.Duration {
	return time.Since(t)
}
