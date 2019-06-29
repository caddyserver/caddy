package caddycmd

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

// Main executes the main function of the caddy command.
func Main() {
	if len(os.Args) <= 1 {
		fmt.Println(usageString())
		return
	}

	subcommand, ok := commands[os.Args[1]]
	if !ok {
		fmt.Printf("%q is not a valid command\n", os.Args[1])
		os.Exit(2)
	}

	if exitCode, err := subcommand(); err != nil {
		log.Println(err)
		os.Exit(exitCode)
	}
}

// commandFunc is a function that executes
// a subcommand. It returns an exit code and
// any associated error.
type commandFunc func() (int, error)

var commands = map[string]commandFunc{
	"start":        cmdStart,
	"stop":         cmdStop,
	"run":          cmdRun,
	"version":      cmdVersion,
	"list-modules": cmdListModules,
	"environ":      cmdEnviron,
}

func usageString() string {
	buf := new(bytes.Buffer)
	buf.WriteString("usage: caddy <command> [<args>]")
	flag.CommandLine.SetOutput(buf)
	flag.CommandLine.PrintDefaults()
	return buf.String()
}

// handlePingbackConn reads from conn and ensures it matches
// the bytes in expect, or returns an error if it doesn't.
func handlePingbackConn(conn net.Conn, expect []byte) error {
	defer conn.Close()
	confirmationBytes, err := ioutil.ReadAll(io.LimitReader(conn, 32))
	if err != nil {
		return err
	}
	if !bytes.Equal(confirmationBytes, expect) {
		return fmt.Errorf("wrong confirmation: %x", confirmationBytes)
	}
	return nil
}
