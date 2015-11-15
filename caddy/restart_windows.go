package caddy

// Restart restarts Caddy forcefully using newCaddyfile,
// or, if nil, the current/existing Caddyfile is reused.
func Restart(newCaddyfile Input) error {
	if newCaddyfile == nil {
		caddyfileMu.Lock()
		newCaddyfile = caddyfile
		caddyfileMu.Unlock()
	}

	wg.Add(1) // barrier so Wait() doesn't unblock

	err := Stop()
	if err != nil {
		return err
	}

	err = Start(newCaddyfile)
	if err != nil {
		return err
	}

	wg.Done() // take down our barrier

	return nil
}
