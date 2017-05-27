// +build !linux appengine

package dns

import (
	"net"
)

// These do nothing. See udp_linux.go for an example of how to implement this.

// We tried to adhire to some kind of naming scheme.
func setUDPSocketOptions(conn *net.UDPConn) error                  { return nil }
func setUDPSocketOptions4(conn *net.UDPConn) error                 { return nil }
func setUDPSocketOptions6(conn *net.UDPConn) error                 { return nil }
func getUDPSocketOptions6Only(conn *net.UDPConn) (bool, error)     { return false, nil }
