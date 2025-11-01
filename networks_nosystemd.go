//go:build !linux || nosystemd

package caddy

func IsReservedNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6" ||
		network == "udp" || network == "udp4" || network == "udp6" ||
		IsUnixNetwork(network) ||
		IsIpNetwork(network) ||
		IsFdNetwork(network)
}

func getListenerFromNetwork(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	return getListenerFromPlugin(ctx, network, host, port, portOffset, config)
}

func getHTTP3Network(originalNetwork string) (string, error) {
	switch originalNetwork {
	case "unixgram":
		return "unixgram", nil
	case "udp":
		return "udp", nil
	case "udp4":
		return "udp4", nil
	case "udp6":
		return "udp6", nil
	case "tcp":
		return "udp", nil
	case "tcp4":
		return "udp4", nil
	case "tcp6":
		return "udp6", nil
	case "fdgram":
		return "fdgram", nil
	}
	return getHTTP3Plugin(originalNetwork)
}
