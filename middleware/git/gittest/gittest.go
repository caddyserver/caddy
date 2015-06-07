// Package gittest is a test package for the git middleware.
// It implements a mock gitos.OS, gitos.Cmd and gitos.File.
package gittest

import (
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/mholt/caddy/middleware/git/gitos"
)

// FakeOS implements a mock gitos.OS, gitos.Cmd and gitos.File.
var FakeOS = fakeOS{}

// CmdOutput is the output of any call to the mocked gitos.Cmd's Output().
var CmdOutput = "success"

// TempFileName is the name of any file returned by mocked gitos.OS's TempFile().
var TempFileName = "tempfile"

// TimeSpeed is how faster the mocked gitos.Ticker and gitos.Sleep should run.
var TimeSpeed = 5

// dirs mocks a fake git dir if filename is "gitdir".
var dirs = map[string][]os.FileInfo{
	"gitdir": {
		fakeInfo{name: ".git", dir: true},
	},
}

// Open creates a new mock gitos.File.
func Open(name string) gitos.File {
	return &fakeFile{name: name}
}

// Sleep calls fake time.Sleep
func Sleep(d time.Duration) {
	FakeOS.Sleep(d)
}

// NewLogger creates a logger that logs to f
func NewLogger(f gitos.File) *log.Logger {
	return log.New(f, "", 0)
}

// fakeFile is a mock gitos.File.
type fakeFile struct {
	name    string
	dir     bool
	content []byte
	info    fakeInfo
	sync.Mutex
}

func (f fakeFile) Name() string {
	return f.name
}

func (f fakeFile) Stat() (os.FileInfo, error) {
	return fakeInfo{name: f.name}, nil
}

func (f fakeFile) Close() error {
	return nil
}

func (f fakeFile) Chmod(mode os.FileMode) error {
	f.info.mode = mode
	return nil
}

func (f *fakeFile) Read(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()
	if len(f.content) == 0 {
		return 0, io.EOF
	}
	n := copy(b, f.content)
	f.content = f.content[n:]
	return n, nil
}

func (f *fakeFile) Write(b []byte) (int, error) {
	f.Lock()
	defer f.Unlock()
	f.content = append(f.content, b...)
	return len(b), nil
}

// fakeCmd is a mock gitos.Cmd.
type fakeCmd struct{}

func (f fakeCmd) Run() error {
	return nil
}

func (f fakeCmd) Start() error {
	return nil
}

func (f fakeCmd) Wait() error {
	return nil
}

func (f fakeCmd) Output() ([]byte, error) {
	return []byte(CmdOutput), nil
}

func (f fakeCmd) Dir(dir string) {}

func (f fakeCmd) Stdin(stdin io.Reader) {}

func (f fakeCmd) Stdout(stdout io.Writer) {}

func (f fakeCmd) Stderr(stderr io.Writer) {}

// fakeInfo is a mock os.FileInfo.
type fakeInfo struct {
	name string
	dir  bool
	mode os.FileMode
}

func (f fakeInfo) Name() string {
	return f.name
}

func (f fakeInfo) Size() int64 {
	return 1024
}

func (f fakeInfo) Mode() os.FileMode {
	return f.mode
}

func (f fakeInfo) ModTime() time.Time {
	return time.Now().Truncate(time.Hour)
}

func (f fakeInfo) IsDir() bool {
	return f.dir
}

func (f fakeInfo) Sys() interface{} {
	return nil
}

// fakeTicker is a mock gitos.Ticker
type fakeTicker struct {
	*time.Ticker
}

func (f fakeTicker) C() <-chan time.Time {
	return f.Ticker.C
}

// fakeOS is a mock gitos.OS.
type fakeOS struct{}

func (f fakeOS) Mkdir(name string, perm os.FileMode) error {
	return nil
}

func (f fakeOS) MkdirAll(path string, perm os.FileMode) error {
	return nil
}

func (f fakeOS) Stat(name string) (os.FileInfo, error) {
	return fakeInfo{name: name}, nil
}

func (f fakeOS) Remove(name string) error {
	return nil
}

func (f fakeOS) LookPath(file string) (string, error) {
	return "/usr/bin/" + file, nil
}

func (f fakeOS) TempFile(dir, prefix string) (gitos.File, error) {
	return &fakeFile{name: TempFileName, info: fakeInfo{name: TempFileName}}, nil
}

func (f fakeOS) ReadDir(dirname string) ([]os.FileInfo, error) {
	if f, ok := dirs[dirname]; ok {
		return f, nil
	}
	return nil, nil
}

func (f fakeOS) Command(name string, args ...string) gitos.Cmd {
	return fakeCmd{}
}

func (f fakeOS) Sleep(d time.Duration) {
	time.Sleep(d / time.Duration(TimeSpeed))
}

func (f fakeOS) NewTicker(d time.Duration) gitos.Ticker {
	return &fakeTicker{time.NewTicker(d / time.Duration(TimeSpeed))}
}

func (f fakeOS) TimeSince(t time.Time) time.Duration {
	return time.Since(t) * time.Duration(TimeSpeed)
}
