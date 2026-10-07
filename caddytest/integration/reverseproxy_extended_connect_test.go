package integration

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/caddyserver/caddy/v2/caddytest"
)

var errExtendedConnectUnsupportedByPeer = errors.New("peer did not advertise RFC 8441 extended CONNECT support")

func TestReverseProxyExtendedConnectOverH2(t *testing.T) {
	tester := caddytest.NewTester(t)
	backend := newWebsocketUpgradeEchoBackend(t)
	defer backend.Close()

	tester.InitServer(fmt.Sprintf(`
{
	admin localhost:2999
	http_port 9080
	https_port 9443
	grace_period 1ns
	skip_install_trust
	servers :9443 {
		protocols h2
	}
}

https://localhost:9443 {
	reverse_proxy %s
}
`, backend.addr), "caddyfile")

	const payload = "extended-connect-echo\n"
	if err := assertExtendedConnectH2Echo("localhost:9443", payload); err != nil {
		if errors.Is(err, errExtendedConnectUnsupportedByPeer) {
			t.Skipf("skipping extended CONNECT integration test: %v", err)
		}
		t.Fatalf("extended connect h2 echo failed: %v", err)
	}
}

func assertExtendedConnectH2Echo(addr, payload string) error {
	conn, err := tlsDialH2(addr)
	if err != nil {
		return fmt.Errorf("dialing h2 tls: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}

	fr := http2.NewFramer(conn, conn)

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return fmt.Errorf("writing client preface: %w", err)
	}
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}); err != nil {
		return fmt.Errorf("writing client settings: %w", err)
	}

	supported, err := waitForServerSettings(fr)
	if err != nil {
		return err
	}
	if !supported {
		return errExtendedConnectUnsupportedByPeer
	}
	if err := waitForSettingsAck(fr); err != nil {
		return err
	}

	if err := writeExtendedConnectHeaders(fr, addr); err != nil {
		return err
	}

	status, err := readResponseStatus(fr, 1)
	if err != nil {
		return err
	}
	if status != "200" {
		return fmt.Errorf("unexpected extended connect status: got=%s want=200", status)
	}

	if err := fr.WriteData(1, false, []byte(payload)); err != nil {
		return fmt.Errorf("writing stream data: %w", err)
	}

	echo, err := readStreamData(fr, 1, len(payload))
	if err != nil {
		return err
	}
	if echo != payload {
		return fmt.Errorf("unexpected echoed payload: got=%q want=%q", echo, payload)
	}

	_ = fr.WriteRSTStream(1, http2.ErrCodeNo)
	return nil
}

func tlsDialH2(addr string) (net.Conn, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, lastErr
}

func waitForServerSettings(fr *http2.Framer) (bool, error) {
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return false, fmt.Errorf("reading frame before connect: %w", err)
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok {
			continue
		}
		if settings.IsAck() {
			continue
		}

		supported := false
		if err := settings.ForeachSetting(func(s http2.Setting) error {
			if s.ID == http2.SettingEnableConnectProtocol && s.Val == 1 {
				supported = true
			}
			return nil
		}); err != nil {
			return false, fmt.Errorf("reading server settings: %w", err)
		}

		if err := fr.WriteSettingsAck(); err != nil {
			return false, fmt.Errorf("writing settings ack: %w", err)
		}
		return supported, nil
	}
}

func waitForSettingsAck(fr *http2.Framer) error {
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return fmt.Errorf("reading settings ack: %w", err)
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if ok && settings.IsAck() {
			return nil
		}
	}
}

func writeExtendedConnectHeaders(fr *http2.Framer, addr string) error {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: addr},
		{Name: ":path", Value: "/upgrade"},
		{Name: ":protocol", Value: "websocket"},
	} {
		if err := enc.WriteField(hf); err != nil {
			return fmt.Errorf("encoding request headers: %w", err)
		}
	}

	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hb.Bytes(),
		EndHeaders:    true,
		EndStream:     false,
	}); err != nil {
		return fmt.Errorf("writing extended connect headers: %w", err)
	}
	return nil
}

func readResponseStatus(fr *http2.Framer, streamID uint32) (string, error) {
	var block bytes.Buffer

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return "", fmt.Errorf("reading response headers: %w", err)
		}
		if rst, ok := frame.(*http2.RSTStreamFrame); ok && rst.StreamID == streamID {
			return "", fmt.Errorf("stream reset before response headers: %s", rst.ErrCode)
		}

		h, ok := frame.(*http2.HeadersFrame)
		if !ok || h.StreamID != streamID {
			continue
		}

		if _, err := block.Write(h.HeaderBlockFragment()); err != nil {
			return "", fmt.Errorf("buffering response header fragment: %w", err)
		}
		for !h.HeadersEnded() {
			next, err := fr.ReadFrame()
			if err != nil {
				return "", fmt.Errorf("reading continuation frame: %w", err)
			}
			c, ok := next.(*http2.ContinuationFrame)
			if !ok || c.StreamID != streamID {
				continue
			}
			if _, err := block.Write(c.HeaderBlockFragment()); err != nil {
				return "", fmt.Errorf("buffering continuation fragment: %w", err)
			}
			if c.HeadersEnded() {
				break
			}
		}
		break
	}

	var status string
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			status = f.Value
		}
	})
	if _, err := dec.Write(block.Bytes()); err != nil {
		return "", fmt.Errorf("decoding response header block: %w", err)
	}
	if status == "" {
		return "", fmt.Errorf("missing :status in response headers")
	}
	return status, nil
}

func readStreamData(fr *http2.Framer, streamID uint32, n int) (string, error) {
	buf := make([]byte, 0, n)
	for len(buf) < n {
		frame, err := fr.ReadFrame()
		if err != nil {
			return "", fmt.Errorf("reading stream data: %w", err)
		}
		d, ok := frame.(*http2.DataFrame)
		if !ok || d.StreamID != streamID {
			continue
		}
		buf = append(buf, d.Data()...)
	}
	return string(buf[:n]), nil
}

type websocketUpgradeEchoBackend struct {
	addr   string
	ln     net.Listener
	server *http.Server
}

func newWebsocketUpgradeEchoBackend(t *testing.T) *websocketUpgradeEchoBackend {
	t.Helper()

	backend := &websocketUpgradeEchoBackend{}
	backend.server = &http.Server{
		Handler: http.HandlerFunc(backend.serveHTTP),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for websocket backend: %v", err)
	}
	backend.ln = ln
	backend.addr = ln.Addr().String()

	go func() {
		_ = backend.server.Serve(ln)
	}()

	return backend
}

func (b *websocketUpgradeEchoBackend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}

	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	_ = rw.Flush()

	go func() {
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
}

func (b *websocketUpgradeEchoBackend) Close() {
	_ = b.server.Close()
	_ = b.ln.Close()
}
