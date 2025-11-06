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
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
)

// IsUnixNetwork returns true if the netw is a unix network.
func IsUnixNetwork(netw string) bool {
	return netw == "unix" || netw == "unixgram" || netw == "unixpacket" || netw == "unix+h2c"
}

func IsTCPNetwork(netw string) bool {
	return netw == "tcp" || netw == "tcp4" || netw == "tcp6"
}

func IsUDPNetwork(netw string) bool {
	return netw == "udp" || netw == "udp4" || netw == "udp6"
}

// IsIpNetwork returns true if the netw is an ip network.
func IsIpNetwork(netw string) bool {
	return strings.HasPrefix(netw, "ip:") || strings.HasPrefix(netw, "ip4:") || strings.HasPrefix(netw, "ip6:")
}

// IsFdNetwork returns true if the netw is a fd network.
func IsFdNetwork(netw string) bool {
	return netw == "fd" || netw == "fdgram"
}

func IsReservedNetwork(network string) bool {
	return IsTCPNetwork(network) ||
		IsUDPNetwork(network) ||
		IsUnixNetwork(network) ||
		IsIpNetwork(network) ||
		IsFdNetwork(network)
}

func IsIPv4Network(netw string) bool {
	return netw == "tcp" || netw == "tcp4" || netw == "udp" || netw == "udp4" || strings.HasPrefix(netw, "ip:") || strings.HasPrefix(netw, "ip4:")
}

func IsIPv6Network(netw string) bool {
	return netw == "tcp" || netw == "tcp6" || netw == "udp" || netw == "udp6" || strings.HasPrefix(netw, "ip:") || strings.HasPrefix(netw, "ip6:")
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

var networkHTTP3Plugins = map[string]string{}

// RegisterNetworkHTTP3 registers a mapping from non-HTTP/3 network to HTTP/3
// network. This should be called during init() and will panic if the network
// type is standard, reserved, or already registered.
//
// EXPERIMENTAL: Subject to change.
func RegisterNetworkHTTP3(originalNetwork, h3Network string) {
	if IsReservedNetwork(originalNetwork) {
		panic("network type " + originalNetwork + " is reserved")
	}
	if _, ok := networkHTTP3Plugins[strings.ToLower(originalNetwork)]; ok {
		panic("network type " + originalNetwork + " is already registered")
	}

	networkHTTP3Plugins[originalNetwork] = h3Network
}

func getHTTP3Plugin(originalNetwork string) (string, error) {
	h3Network, ok := networkHTTP3Plugins[strings.ToLower(originalNetwork)]
	if !ok {
		return "", fmt.Errorf("network '%s' cannot handle HTTP/3 connections", originalNetwork)
	}

	return h3Network, nil
}

func GetHTTP3Network(originalNetwork string) (string, error) {
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
