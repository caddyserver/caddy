package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/mholt/archiver"
)

var buildScript, repoDir, mainDir, distDir, buildDir, releaseDir string

func init() {
	repoDir = filepath.Join(os.Getenv("GOPATH"), "src", "github.com", "mholt", "caddy")
	mainDir = filepath.Join(repoDir, "caddy")
	buildScript = filepath.Join(mainDir, "build.bash")
	distDir = filepath.Join(repoDir, "dist")
	buildDir = filepath.Join(distDir, "builds")
	releaseDir = filepath.Join(distDir, "release")
}

func main() {
	// First, clean up
	err := os.RemoveAll(buildDir)
	if err != nil {
		log.Fatal(err)
	}
	err = os.RemoveAll(releaseDir)
	if err != nil {
		log.Fatal(err)
	}

	// Then set up
	err = os.MkdirAll(buildDir, 0755)
	if err != nil {
		log.Fatal(err)
	}
	err = os.MkdirAll(releaseDir, 0755)
	if err != nil {
		log.Fatal(err)
	}

	// Perform builds and make archives in parallel; only as many
	// goroutines as we have processors.
	var wg sync.WaitGroup
	var throttle = make(chan struct{}, numProcs())
	for _, p := range platforms {
		wg.Add(1)
		throttle <- struct{}{}

		if p.os == "" || p.arch == "" || p.archive == "" {
			log.Fatalf("Platform OS, architecture, and archive format is required: %+v", p)
		}

		go func(p platform) {
			defer wg.Done()
			defer func() { <-throttle }()

			fmt.Printf("== Building %s\n", p)

			var baseFilename, binFilename string
			baseFilename = fmt.Sprintf("caddy_%s_%s", p.os, p.arch)
			if p.arch == "arm" {
				baseFilename += p.arm
			}
			binFilename = baseFilename + p.binExt

			binPath := filepath.Join(buildDir, binFilename)
			archive := filepath.Join(releaseDir, fmt.Sprintf("%s.%s", baseFilename, p.archive))
			archiveContents := append(distContents, binPath)

			err := build(p, binPath)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("== Compressing %s\n", baseFilename)

			if p.archive == "zip" {
				err := archiver.Zip.Make(archive, archiveContents)
				if err != nil {
					log.Fatal(err)
				}
			} else if p.archive == "tar.gz" {
				err := archiver.TarGz.Make(archive, archiveContents)
				if err != nil {
					log.Fatal(err)
				}
			}
		}(p)
	}

	wg.Wait()
}

func build(p platform, out string) error {
	cmd := exec.Command(buildScript, out)
	cmd.Dir = mainDir
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	cmd.Env = append(cmd.Env, "GOOS="+p.os)
	cmd.Env = append(cmd.Env, "GOARCH="+p.arch)
	cmd.Env = append(cmd.Env, "GOARM="+p.arm)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type platform struct {
	os, arch, arm, binExt, archive string
}

func (p platform) String() string {
	outStr := fmt.Sprintf("%s/%s", p.os, p.arch)
	if p.arch == "arm" {
		outStr += fmt.Sprintf(" (ARM v%s)", p.arm)
	}
	return outStr
}

func numProcs() int {
	n := runtime.GOMAXPROCS(0)
	if n == runtime.NumCPU() && n > 1 {
		n--
	}
	return n
}

// See: https://golang.org/doc/install/source#environment
// Not all supported platforms are listed since some are
// problematic and we only build the most common ones.
// These are just the pre-made, readily-available static
// builds, and we can try to add more upon request if there
// is enough demand.
var platforms = []platform{
	{os: "darwin", arch: "amd64", archive: "zip"},
	{os: "freebsd", arch: "386", archive: "tar.gz"},
	{os: "freebsd", arch: "amd64", archive: "tar.gz"},
	{os: "freebsd", arch: "arm", arm: "7", archive: "tar.gz"},
	{os: "linux", arch: "386", archive: "tar.gz"},
	{os: "linux", arch: "amd64", archive: "tar.gz"},
	{os: "linux", arch: "arm", arm: "7", archive: "tar.gz"},
	{os: "linux", arch: "arm64", archive: "tar.gz"},
	{os: "netbsd", arch: "386", archive: "tar.gz"},
	{os: "netbsd", arch: "amd64", archive: "tar.gz"},
	{os: "openbsd", arch: "386", archive: "tar.gz"},
	{os: "openbsd", arch: "amd64", archive: "tar.gz"},
	{os: "solaris", arch: "amd64", archive: "tar.gz"},
	{os: "windows", arch: "386", binExt: ".exe", archive: "zip"},
	{os: "windows", arch: "amd64", binExt: ".exe", archive: "zip"},
}

var distContents = []string{
	filepath.Join(distDir, "init"),
	filepath.Join(distDir, "CHANGES.txt"),
	filepath.Join(distDir, "LICENSES.txt"),
	filepath.Join(distDir, "README.txt"),
}
