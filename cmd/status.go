package caddycmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	RegisterCommand(Command{
		Name:  "status",
		Func:  cmdStatus,
		Usage: "[--json] [--address <admin-api-address>] [--config <path>] [--adapter <name>]",
		Short: "Prints the status of the running Caddy instance",
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("status", flag.ExitOnError)
			fs.Bool("json", false, "Output raw JSON instead of human-readable text")
			fs.String("address", "", "The address to use to reach the admin API endpoint, if not the default")
			fs.String("config", "", "Configuration file")
			fs.String("adapter", "", "Name of config adapter to apply")
			return fs
		}(),
	})
}

// cmdStatus implements the 'caddy status' command.
func cmdStatus(fl Flags) (int, error) {
	useJSON := fl.Bool("json")
	addr := fl.String("address")
	cfgFile := fl.String("config")
	cfgAdapter := fl.String("adapter")

	// Determine the admin API address based on provided flags or defaults
	adminAddr, err := DetermineAdminAPIAddress(cfgFile, nil, cfgAdapter, addr)
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("could not determine admin API address: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/status", adminAddr))
	if err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to reach admin API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return caddy.ExitCodeFailedStartup, err
	}

	if useJSON {
		fmt.Println(string(body))
		return caddy.ExitCodeSuccess, nil
	}

	var status map[string]any
	if err := json.Unmarshal(body, &status); err != nil {
		return caddy.ExitCodeFailedStartup, fmt.Errorf("failed to parse status JSON: %v\nRaw output: %s", err, string(body))
	}

	// Format output to be human-readable
	fmt.Printf("Caddy %v\n", status["version"])
	fmt.Println("Status: Running")

	if uptime, ok := status["uptime_secs"].(float64); ok {
		u := int64(uptime)
		h := u / 3600
		m := (u % 3600) / 60
		s := u % 60
		if h > 0 {
			fmt.Printf("Uptime: %dh %dm %ds\n", h, m, s)
		} else if m > 0 {
			fmt.Printf("Uptime: %dm %ds\n", m, s)
		} else {
			fmt.Printf("Uptime: %ds\n", s)
		}
	}

	if apps, ok := status["apps"].(map[string]any); ok && len(apps) > 0 {
		var appNames []string
		for appName := range apps {
			appNames = append(appNames, appName)
		}
		fmt.Printf("\nRunning apps: %s\n", strings.Join(appNames, ", "))
	} else {
		fmt.Printf("\nRunning apps: none\n")
	}

	fmt.Println("\nMemory")
	if mem, ok := status["memory"].(map[string]any); ok {
		allocMB := mem["allocated_bytes"].(float64) / 1024 / 1024
		sysMB := mem["system_bytes"].(float64) / 1024 / 1024
		fmt.Printf("Allocated: %.0f MB\nSystem: %.0f MB\n", allocMB, sysMB)
	}

	fmt.Printf("Goroutines: %v\n", status["goroutines"])

	return caddy.ExitCodeSuccess, nil
}
