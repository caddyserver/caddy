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

//go:build linux

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const systemdListenHelper = "CADDY_SYSTEMD_LISTEN_HELPER"

func TestSystemdListenFDIntegration(t *testing.T) {
	if os.Getenv(systemdListenHelper) == "1" {
		runSystemdListenFDHelper(t)
		return
	}

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpFile, err := tcpListener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	_ = tcpListener.Close()
	defer tcpFile.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udpFile, err := udpConn.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = udpConn.Close()
	defer udpFile.Close()

	h3Conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h3File, err := h3Conn.File()
	if err != nil {
		t.Fatal(err)
	}
	_ = h3Conn.Close()
	defer h3File.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSystemdListenFDIntegration$", "-test.v")
	cmd.ExtraFiles = []*os.File{tcpFile, udpFile, h3File}
	cmd.Env = append(withoutSystemdListenEnv(os.Environ()),
		systemdListenHelper+"=1",
		"LISTEN_FDS=3",
		"LISTEN_FDNAMES=web:dns:dns",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func runSystemdListenFDHelper(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	repl := caddy.NewReplacer()

	stream := resolveSystemdListenAddress(t, repl, "fd/{systemd.listen.web}", "fd/3")
	lnAny, err := stream.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ln, ok := lnAny.(net.Listener)
	if !ok {
		t.Fatalf("stream listener has type %T", lnAny)
	}
	defer ln.Close()
	checkInheritedStream(t, ln)
	if _, err := repl.ReplaceOrErr("fd/{systemd.listen.missing}", true, true); err == nil {
		t.Fatal("unknown descriptor name did not fail replacement")
	}

	// The inherited descriptor mapping belongs to the process. Keep using the
	// first valid snapshot even if later code changes the environment.
	t.Setenv("LISTEN_FDNAMES", "changed")

	datagram := resolveSystemdListenAddress(t, repl, "fdgram/{systemd.listen.dns}", "fdgram/4")
	pcAny, err := datagram.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	pc, ok := pcAny.(net.PacketConn)
	if !ok {
		t.Fatalf("datagram listener has type %T", pcAny)
	}
	defer pc.Close()
	checkInheritedDatagram(t, pc)

	h3 := resolveSystemdListenAddress(t, repl, "fdgram/{systemd.listen.dns:1}", "fdgram/5")
	var tlsConfig *tls.Config
	tlsConfig = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return tlsConfig, nil
		},
	}
	quicListener, err := h3.ListenQUIC(context.Background(), 0, net.ListenConfig{}, tlsConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := quicListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := quicListener.Close(); err != nil {
		t.Fatal(err)
	}
}

func resolveSystemdListenAddress(t *testing.T, repl *caddy.Replacer, input, want string) caddy.NetworkAddress {
	t.Helper()
	resolved, err := repl.ReplaceOrErr(input, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want {
		t.Fatalf("resolved address = %q; want %q", resolved, want)
	}
	address, err := caddy.ParseNetworkAddress(resolved)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func checkInheritedStream(t *testing.T, ln net.Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "ping" {
			err = fmt.Errorf("received %q; want ping", buf)
		}
		done <- err
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write([]byte("ping"))
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inherited listener")
	}
}

func checkInheritedDatagram(t *testing.T, pc net.PacketConn) {
	t.Helper()
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("received %q; want ping", buf[:n])
	}
}

func withoutSystemdListenEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "LISTEN_PID=") ||
			strings.HasPrefix(entry, "LISTEN_PIDFDID=") ||
			strings.HasPrefix(entry, "LISTEN_FDS=") ||
			strings.HasPrefix(entry, "LISTEN_FDNAMES=") ||
			strings.HasPrefix(entry, systemdListenHelper+"=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
