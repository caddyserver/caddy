package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/bifurcation/mint"
)

var url string

func main() {
	url := flag.String("url", "https://localhost:4430", "URL to send request")
	flag.Parse()
	mintdial := func(network, addr string) (net.Conn, error) {
		return mint.Dial(network, addr, nil)
	}

	tr := &http.Transport{
		DialTLS:            mintdial,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(*url)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(contents))
}
