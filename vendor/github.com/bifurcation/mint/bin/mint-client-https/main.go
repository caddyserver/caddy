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
var dontValidate bool

func main() {
	c := mint.Config{}

	url := flag.String("url", "https://localhost:4430", "URL to send request")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}

	mintdial := func(network, addr string) (net.Conn, error) {
		return mint.Dial(network, addr, &c)
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
