// +build !openbsd

package caddy

// pledge is a no-op on any operating system that isn't OpenBSD.
func pledge() {
}
