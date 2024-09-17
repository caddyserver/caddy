package internal

// PrivateRangesCIDR returns a list of private CIDR range
// strings, which can be used as a configuration shortcut.
func PrivateRangesCIDR() []string {
	return []string{
		"192.168.0.0/16",
		"172.16.0.0/12",
		"10.0.0.0/8",
		"127.0.0.1/8",
		"fd00::/8",
		"::1",
	}
}
