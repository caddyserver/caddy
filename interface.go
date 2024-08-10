package caddy

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func init() {
	RegisterNetwork("iface", getInterfaceListener)
	RegisterNetwork("iface+tcp", getInterfaceListener)
	RegisterNetwork("iface+udp", getInterfaceListener)
}

func getInterfaceListener(ctx context.Context, network, addr string, config net.ListenConfig) (any, error) {
	// assuming addr = "interface+family:port"
	// if family is missing, then assume tcp
	family := "tcp"
	parts := strings.Split(network, "+")
	if len(parts) == 2 {
		family = parts[1]
	}
	host, port, _ := net.SplitHostPort(addr)
	iface, err := net.InterfaceByName(host)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found", addr)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("error on obtaining interface %s addresses: %s", iface.Name, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("interface %s has no addresses", iface.Name)
	}
	for _, addr := range addrs {
		if face, ok := addr.(*net.IPNet); ok {
			if ip4 := face.IP.To4(); ip4 != nil {
				switch family {
				case "tcp":
					return net.Listen(family, net.JoinHostPort(ip4.String(), port))
				case "udp":
					return net.ListenPacket(family, net.JoinHostPort(ip4.String(), port))
				default:
					return net.Listen(family, net.JoinHostPort(ip4.String(), port))
				}
			}
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 addresses", iface.Name)
}
