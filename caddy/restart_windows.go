package caddy

import "log"

// Restart restarts Caddy forcefully using newCaddyfile,
// or, if nil, the current/existing Caddyfile is reused.
func Restart(newCaddyfile Input) error {
	log.Println("[INFO] Restarting")

	caddyfileMu.Lock()
	oldCaddyfile := caddyfile
	if newCaddyfile == nil {
		newCaddyfile = caddyfile
	}
	caddyfileMu.Unlock()

	wg.Add(1) // barrier so Wait() doesn't unblock

	err := Stop()
	if err != nil {
		return err
	}

	err = Start(newCaddyfile)
	if err != nil {
		// revert to old Caddyfile
		if oldErr := Start(oldCaddyfile); oldErr != nil {
			log.Printf("[ERROR] Restart: in-process restart failed and cannot revert to old Caddyfile: %v", oldErr)
		} else {
			wg.Done() // take down our barrier
		}
		return err
	}

	wg.Done() // take down our barrier

	return nil
}
