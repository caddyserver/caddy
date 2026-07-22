// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddy

import (
	"context"
	"net"
	"strings"

	"go.uber.org/zap"
)

const (
	UNIX       = "unix"
	UNIX_H2C   = "unix+h2c"
	UNIXGRAM   = "unixgram"
	UNIXPACKET = "unixpacket"
	TCP        = "tcp"
	TCP4       = "tcp4"
	TCP6       = "tcp6"
	UDP        = "udp"
	UDP4       = "udp4"
	UDP6       = "udp6"
	IP_        = "ip:"
	IP4_       = "ip4:"
	IP6_       = "ip6:"
	FD         = "fd"
	FDGRAM     = "fdgram"
)

// IsUnixNetwork returns true if the netw is a unix network.
func IsUnixNetwork(netw string) bool {
	return netw == UNIX || netw == UNIX_H2C || netw == UNIXGRAM || netw == UNIXPACKET
}

// IsUnixNetwork returns true if the netw is a TCP network.
func IsTCPNetwork(netw string) bool {
	return netw == TCP || netw == TCP4 || netw == TCP6
}

// IsUnixNetwork returns true if the netw is a UDP network.
func IsUDPNetwork(netw string) bool {
	return netw == UDP || netw == UDP4 || netw == UDP6
}

// IsIPNetwork returns true if the netw is an ip network.
func IsIPNetwork(netw string) bool {
	return strings.HasPrefix(netw, IP_) || strings.HasPrefix(netw, IP4_) || strings.HasPrefix(netw, IP6_)
}

// IsFDNetwork returns true if the netw is a fd network.
func IsFDNetwork(netw string) bool {
	return netw == FD || netw == FDGRAM
}

func IsReservedNetwork(network string) bool {
	return IsUnixNetwork(network) ||
		IsTCPNetwork(network) ||
		IsUDPNetwork(network) ||
		IsIPNetwork(network) ||
		IsFDNetwork(network)
}

func IsIPv4Network(netw string) bool {
	return netw == TCP || netw == TCP4 || netw == UDP || netw == UDP4 || strings.HasPrefix(netw, IP_) || strings.HasPrefix(netw, IP4_)
}

func IsIPv6Network(netw string) bool {
	return netw == TCP || netw == TCP6 || netw == UDP || netw == UDP6 || strings.HasPrefix(netw, IP_) || strings.HasPrefix(netw, IP6_)
}

func IsStreamNetwork(netw string) bool {
	return netw == UNIX || netw == UNIX_H2C || netw == UNIXPACKET || IsTCPNetwork(netw) || netw == FD
}

func IsPacketNetwork(netw string) bool {
	return netw == UNIXGRAM || IsUDPNetwork(netw) || IsIPNetwork(netw) || netw == FDGRAM
}

// ListenerFunc is a function that can return a listener given a network and address.
// The listeners must be capable of overlapping: with Caddy, new configs are loaded
// before old ones are unloaded, so listeners may overlap briefly if the configs
// both need the same listener. EXPERIMENTAL and subject to change.
type ListenerFunc func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error)

var networkPlugins = map[string]ListenerFunc{}

// RegisterNetwork registers a network plugin with Caddy so that if a listener is
// created for that network plugin, getListener will be invoked to get the listener.
// This should be called during init() and will panic if the network type is standard
// or reserved, or if it is already registered. EXPERIMENTAL and subject to change.
func RegisterNetwork(network string, getListener ListenerFunc) {
	network = strings.TrimSpace(strings.ToLower(network))

	if IsReservedNetwork(network) {
		panic("network type " + network + " is reserved")
	}

	if _, ok := networkPlugins[strings.ToLower(network)]; ok {
		panic("network type " + network + " is already registered")
	}

	networkPlugins[network] = getListener
}

// getListenerFromPlugin returns a listener on the given network and address
// if a plugin has registered the network name. It may return (nil, nil) if
// no plugin can provide a listener.
func getListenerFromPlugin(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	// get listener from plugin if network is registered
	if getListener, ok := networkPlugins[network]; ok {
		Log().Debug("getting listener from plugin", zap.String("network", network))
		return getListener(ctx, network, host, port, portOffset, config)
	}

	return nil, nil
}
