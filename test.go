package main

import (
	"fmt"
	"net"
)

func main() {
	a, _ := net.Interfaces()
	for _, ifc := range a {
		fmt.Println(ifc)
		addrs, err := ifc.Addrs()
		fmt.Println(err)
		for _, addr := range addrs {
			fmt.Println(addr.String())
			// prefix, err := netip.ParsePrefix(addr.String())
			// fmt.Println(err)
			// fmt.Println(prefix)
			// fmt.Println(prefix.Addr())
		}
	}
}
