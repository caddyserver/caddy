package caddy

import "log"

// Restart restarts Caddy forcefully using newCaddyfile,
// or, if nil, the current/existing Caddyfile is reused.
func Restart(newCaddyfile Input) error {
	log.Println("[INFO] Restarting")

	if newCaddyfile == nil {
		caddyfileMu.Lock()
		newCaddyfile = caddyfile
		caddyfileMu.Unlock()
	}

	return restartInProc(newCaddyfile)
}
