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
	"net/netip"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// IsUnixNetwork returns true if the netw is a unix network.
func IsUnixNetwork(netw string) bool {
	return netw == "unix" || netw == "unixgram" || netw == "unixpacket" || netw == "unix+h2c"
}

// IsIpNetwork returns true if the netw is an ip network.
func IsIpNetwork(netw string) bool {
	return strings.HasPrefix(netw, "ip:") || strings.HasPrefix(netw, "ip4:") || strings.HasPrefix(netw, "ip6:")
}

// IsFdNetwork returns true if the netw is a fd network.
func IsFdNetwork(netw string) bool {
	return netw == "fd" || netw == "fdgram"
}

// IsIfaceNetwork returns true if the netw is an iface network.
func IsIfaceNetwork(netw string) bool {
	return netw == "iface" || netw == "iface4" || netw == "iface6" || netw == "ifacegram" || netw == "ifacegram4" || netw == "ifacegram6"
}

// ListenerFunc is a function that can return a listener given a network and address.
// The listeners must be capable of overlapping: with Caddy, new configs are loaded
// before old ones are unloaded, so listeners may overlap briefly if the configs
// both need the same listener. EXPERIMENTAL and subject to change.
type ListenerFunc func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error)

var (
	networkPlugins   = map[string]ListenerFunc{}
	networkPluginsMu sync.RWMutex
)

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

	networkPluginsMu.Lock()
	defer networkPluginsMu.Unlock()

	networkPlugins[network] = getListener
}

func getListenerFromIface(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	iface, err := net.InterfaceByName(host)
	if err != nil {
		return nil, err
	}

	var (
		addrs []net.Addr
		err error
	)
	switch network {
		case "iface": fallthrough
		case "iface4": fallthrough
		case "iface6":
			unicast, err = iface.Addrs()
			if err != nil {
				//todo
			} else {
				addrs = append(addrs, unicast...)
			}
		case "ifacegram": fallthrough
		case "ifacegram4": fallthrough
		case "ifacegram6":
			multicast, err = iface.MulticastAddrs()
			if err != nil {
				//todo
			} else {
				addrs = append(addrs, multicast...)
			}
	}
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		switch addrt := addr.(type) {
			case *net.IPAddr:

			case *net.IPNet:

		}
		prefix, err := netip.ParsePrefix(addr.String())
		preaddr := prefix.Addr()
		if(preaddr.Is4()) {
			switch network {
				case "iface": fallthrough
				case "iface4": fallthrough
				case "ifacegram": fallthrough
				case "ifacegram4":
					//todo
			}
		}
		if(preaddr.Is6()) {
			switch network {
				case "iface": fallthrough
				case "iface6": fallthrough
				case "ifacegram": fallthrough
				case "ifacegram6":
					//todo
			}
		}
		if err != nil {
			continue
		}
	}
}

// getListenerFromPlugin returns a listener on the given network and address
// if a plugin has registered the network name. It may return (nil, nil) if
// no plugin can provide a listener.
func getListenerFromPlugin(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	networkPluginsMu.RLock()
	defer networkPluginsMu.RUnlock()

	// get listener from plugin if network is registered
	if getListener, ok := networkPlugins[network]; ok {
		Log().Debug("getting listener from plugin", zap.String("network", network))
		return getListener(ctx, network, host, port, portOffset, config)
	}

	return nil, nil
}

var (
	networkHTTP3Plugins   = map[string]string{}
	networkHTTP3PluginsMu sync.RWMutex
)

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

	networkHTTP3PluginsMu.Lock()
	defer networkHTTP3PluginsMu.Unlock()

	networkHTTP3Plugins[originalNetwork] = h3Network
}

func getHTTP3Plugin(originalNetwork string) (string, error) {
	networkHTTP3PluginsMu.RLock()
	defer networkHTTP3PluginsMu.RUnlock()

	h3Network, ok := networkHTTP3Plugins[strings.ToLower(originalNetwork)]
	if !ok {
		return "", fmt.Errorf("network '%s' cannot handle HTTP/3 connections", originalNetwork)
	}

	return h3Network, nil
}
