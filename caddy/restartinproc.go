package caddy

import "log"

// restartInProc restarts Caddy forcefully in process using newCaddyfile.
func restartInProc(newCaddyfile Input) error {
	wg.Add(1) // barrier so Wait() doesn't unblock
	defer wg.Done()

	err := Stop()
	if err != nil {
		return err
	}

	caddyfileMu.Lock()
	oldCaddyfile := caddyfile
	caddyfileMu.Unlock()

	err = Start(newCaddyfile)
	if err != nil {
		// revert to old Caddyfile
		if oldErr := Start(oldCaddyfile); oldErr != nil {
			log.Printf("[ERROR] Restart: in-process restart failed and cannot revert to old Caddyfile: %v", oldErr)
		}
	}

	return err
}
