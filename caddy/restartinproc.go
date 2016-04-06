package caddy

import "log"

// restartInProc restarts Caddy forcefully in process using newCaddyfile.
func restartInProc(newCaddyfile Input) error {
	wg.Add(1) // barrier so Wait() doesn't unblock

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
		} else {
			wg.Done() // take down our barrier
		}
		return err
	}

	wg.Done() // take down our barrier

	return nil
}
