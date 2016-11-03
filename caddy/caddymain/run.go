package caddymain

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/xenolf/lego/acme"

	"github.com/mholt/caddy"
	// plug in the HTTP server type
	_ "github.com/mholt/caddy/caddyhttp"

	"github.com/mholt/caddy/caddytls"
	// This is where other plugins get plugged in (imported)
)

func init() {
	caddy.TrapSignals()
	setVersion()

	flag.BoolVar(&caddytls.Agreed, "agree", false, "Agree to the CA's Subscriber Agreement")
	flag.StringVar(&caddytls.DefaultCAUrl, "ca", "https://acme-v01.api.letsencrypt.org/directory", "URL to certificate authority's ACME server directory")
	flag.StringVar(&conf, "conf", "", "Caddyfile to load (default \""+caddy.DefaultConfigFile+"\")")
	flag.StringVar(&cpu, "cpu", "100%", "CPU cap")
	flag.BoolVar(&plugins, "plugins", false, "List installed plugins")
	flag.StringVar(&caddytls.DefaultEmail, "email", "", "Default ACME CA account email address")
	flag.DurationVar(&acme.HTTPClient.Timeout, "catimeout", acme.HTTPClient.Timeout, "Default ACME CA HTTP timeout")
	flag.StringVar(&logfile, "log", "", "Process log file")
	flag.StringVar(&caddy.PidFile, "pidfile", "", "Path to write pid file")
	flag.BoolVar(&caddy.Quiet, "quiet", false, "Quiet mode (no initialization output)")
	flag.StringVar(&revoke, "revoke", "", "Hostname for which to revoke the certificate")
	flag.StringVar(&serverType, "type", "http", "Type of server to run")
	flag.BoolVar(&version, "version", false, "Show version")

	caddy.RegisterCaddyfileLoader("flag", caddy.LoaderFunc(confLoader))
	caddy.SetDefaultCaddyfileLoader("default", caddy.LoaderFunc(defaultLoader))
}

// Run is Caddy's main() function.
func Run() {
	flag.Parse()

	caddy.AppName = appName
	caddy.AppVersion = appVersion
	acme.UserAgent = appName + "/" + appVersion

	// Set up process log before anything bad happens
	switch logfile {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	case "":
		log.SetOutput(ioutil.Discard)
	default:
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    100,
			MaxAge:     14,
			MaxBackups: 10,
		})
	}

	// Check for one-time actions
	if revoke != "" {
		err := caddytls.Revoke(revoke)
		if err != nil {
			mustLogFatalf(err.Error())
		}
		fmt.Printf("Revoked certificate for %s\n", revoke)
		os.Exit(0)
	}
	if version {
		fmt.Printf("%s %s\n", appName, appVersion)
		if devBuild && gitShortStat != "" {
			fmt.Printf("%s\n%s\n", gitShortStat, gitFilesModified)
		}
		os.Exit(0)
	}
	if plugins {
		fmt.Println(caddy.DescribePlugins())
		os.Exit(0)
	}

	moveStorage() // TODO: This is temporary for the 0.9 release, or until most users upgrade to 0.9+

	// Set CPU cap
	err := setCPU(cpu)
	if err != nil {
		mustLogFatalf(err.Error())
	}

	// Get Caddyfile input
	caddyfile, err := caddy.LoadCaddyfile(serverType)
	if err != nil {
		mustLogFatalf(err.Error())
	}

	// Start your engines
	instance, err := caddy.Start(caddyfile)
	if err != nil {
		mustLogFatalf(err.Error())
	}

	// Twiddle your thumbs
	instance.Wait()
}

// mustLogFatalf wraps log.Fatalf() in a way that ensures the
// output is always printed to stderr so the user can see it
// if the user is still there, even if the process log was not
// enabled. If this process is an upgrade, however, and the user
// might not be there anymore, this just logs to the process
// log and exits.
func mustLogFatalf(format string, args ...interface{}) {
	if !caddy.IsUpgrade() {
		log.SetOutput(os.Stderr)
	}
	log.Fatalf(format, args...)
}

// confLoader loads the Caddyfile using the -conf flag.
func confLoader(serverType string) (caddy.Input, error) {
	if conf == "" {
		return nil, nil
	}

	if conf == "stdin" {
		return caddy.CaddyfileFromPipe(os.Stdin, serverType)
	}

	contents, err := ioutil.ReadFile(conf)
	if err != nil {
		return nil, err
	}
	return caddy.CaddyfileInput{
		Contents:       contents,
		Filepath:       conf,
		ServerTypeName: serverType,
	}, nil
}

// defaultLoader loads the Caddyfile from the current working directory.
func defaultLoader(serverType string) (caddy.Input, error) {
	contents, err := ioutil.ReadFile(caddy.DefaultConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return caddy.CaddyfileInput{
		Contents:       contents,
		Filepath:       caddy.DefaultConfigFile,
		ServerTypeName: serverType,
	}, nil
}

// moveStorage moves the old certificate storage location by
// renaming the "letsencrypt" folder to the hostname of the
// CA URL. This is TEMPORARY until most users have upgraded to 0.9+.
func moveStorage() {
	oldPath := filepath.Join(caddy.AssetsPath(), "letsencrypt")
	_, err := os.Stat(oldPath)
	if os.IsNotExist(err) {
		return
	}
	// Just use a default config to get default (file) storage
	fileStorage, err := new(caddytls.Config).StorageFor(caddytls.DefaultCAUrl)
	if err != nil {
		mustLogFatalf("[ERROR] Unable to get new path for certificate storage: %v", err)
	}
	newPath := fileStorage.(*caddytls.FileStorage).Path
	err = os.MkdirAll(string(newPath), 0700)
	if err != nil {
		mustLogFatalf("[ERROR] Unable to make new certificate storage path: %v\n\nPlease follow instructions at:\nhttps://github.com/mholt/caddy/issues/902#issuecomment-228876011", err)
	}
	err = os.Rename(oldPath, string(newPath))
	if err != nil {
		mustLogFatalf("[ERROR] Unable to migrate certificate storage: %v\n\nPlease follow instructions at:\nhttps://github.com/mholt/caddy/issues/902#issuecomment-228876011", err)
	}
	// convert mixed case folder and file names to lowercase
	var done bool // walking is recursive and preloads the file names, so we must restart walk after a change until no changes
	for !done {
		done = true
		filepath.Walk(string(newPath), func(path string, info os.FileInfo, err error) error {
			// must be careful to only lowercase the base of the path, not the whole thing!!
			base := filepath.Base(path)
			if lowerBase := strings.ToLower(base); base != lowerBase {
				lowerPath := filepath.Join(filepath.Dir(path), lowerBase)
				err = os.Rename(path, lowerPath)
				if err != nil {
					mustLogFatalf("[ERROR] Unable to lower-case: %v\n\nPlease follow instructions at:\nhttps://github.com/mholt/caddy/issues/902#issuecomment-228876011", err)
				}
				// terminate traversal and restart since Walk needs the updated file list with new file names
				done = false
				return errors.New("start over")
			}
			return nil
		})
	}
}

// setVersion figures out the version information
// based on variables set by -ldflags.
func setVersion() {
	// A development build is one that's not at a tag or has uncommitted changes
	devBuild = gitTag == "" || gitShortStat != ""

	// Only set the appVersion if -ldflags was used
	if gitNearestTag != "" || gitTag != "" {
		if devBuild && gitNearestTag != "" {
			appVersion = fmt.Sprintf("%s (+%s %s)",
				strings.TrimPrefix(gitNearestTag, "v"), gitCommit, buildDate)
		} else if gitTag != "" {
			appVersion = strings.TrimPrefix(gitTag, "v")
		}
	}
}

// setCPU parses string cpu and sets GOMAXPROCS
// according to its value. It accepts either
// a number (e.g. 3) or a percent (e.g. 50%).
func setCPU(cpu string) error {
	var numCPU int

	availCPU := runtime.NumCPU()

	if strings.HasSuffix(cpu, "%") {
		// Percent
		var percent float32
		pctStr := cpu[:len(cpu)-1]
		pctInt, err := strconv.Atoi(pctStr)
		if err != nil || pctInt < 1 || pctInt > 100 {
			return errors.New("invalid CPU value: percentage must be between 1-100")
		}
		percent = float32(pctInt) / 100
		numCPU = int(float32(availCPU) * percent)
	} else {
		// Number
		num, err := strconv.Atoi(cpu)
		if err != nil || num < 1 {
			return errors.New("invalid CPU value: provide a number or percent greater than 0")
		}
		numCPU = num
	}

	if numCPU > availCPU {
		numCPU = availCPU
	}

	runtime.GOMAXPROCS(numCPU)
	return nil
}

const appName = "Caddy"

// Flags that control program flow or startup
var (
	serverType string
	conf       string
	cpu        string
	logfile    string
	revoke     string
	version    bool
	plugins    bool
)

// Build information obtained with the help of -ldflags
var (
	appVersion = "(untracked dev build)" // inferred at startup
	devBuild   = true                    // inferred at startup

	buildDate        string // date -u
	gitTag           string // git describe --exact-match HEAD 2> /dev/null
	gitNearestTag    string // git describe --abbrev=0 --tags HEAD
	gitCommit        string // git rev-parse HEAD
	gitShortStat     string // git diff-index --shortstat
	gitFilesModified string // git diff-index --name-only HEAD
)
