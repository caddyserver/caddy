// +build windows plan9 nacl

package caddy

// checkFdlimit issues a warning if the OS limit for
// max file descriptors is below a recommended minimum.
func checkFdlimit() {
}
