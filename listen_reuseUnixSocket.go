//go:build (!unix || solaris) && !windows

package caddy

func reuseUnixSocket(_, _ string) (any, error) {
	return nil, nil
}
