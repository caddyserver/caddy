package caddycmd

import (
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	defaultFactory.Use(func(rootCmd *cobra.Command) {
		rootCmd.PersistentFlags().String("plugin-dir", "", "Directory to search for Go plugins")
	})
}

func loadPlugins() {
	pluginFs := pflag.NewFlagSet("plugins", pflag.ContinueOnError)
	pluginFs.ParseErrorsWhitelist.UnknownFlags = true
	var pluginDir string
	pluginFs.StringVar(&pluginDir, "plugin-dir", "", "")
	_ = pluginFs.Parse(os.Args[1:])

	if pluginDir == "" {
		return
	}

	switch runtime.GOOS {
    	case "linux", "darwin", "freebsd":
            log.Println("[WARNING] The --plugin-dir flag is an experimental feature")
    	default:
    		log.Printf("[WARNING] Go plugins are not supported on this platform (%s/%s); ignoring --plugin-dir",
    			runtime.GOOS, runtime.GOARCH)
    		return
    	}

	files, err := os.ReadDir(pluginDir)
	if err != nil {
        log.Printf("[WARNING] Failed reading plugin directory, ignoring --plugin-dir %s: %v", pluginDir, err)
		return
	}

	var pluginsToLoad []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".so") {
			pluginsToLoad = append(pluginsToLoad, filepath.Join(pluginDir, file.Name()))
		}
	}

	for _, pluginPath := range pluginsToLoad {
		_, err := plugin.Open(pluginPath)
		if err != nil {
			log.Printf("[ERROR] Loading plugin %s: %v", pluginPath, err)
			os.Exit(caddy.ExitCodeFailedStartup)
		}
	}
}
