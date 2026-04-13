package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// stressCloseDelay is the stream_close_delay used for the close_delay scenario.
// Long enough to outlast all test reloads; short enough to keep total test time reasonable.
const stressCloseDelay = 3 * time.Second

func TestReverseProxyReloadStressUpgradedStreamsHeapProfiles(t *testing.T) {
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{
		LoadRequestTimeout: 30 * time.Second,
		TestRequestTimeout: 30 * time.Second,
	})

	backend := newUpgradeEchoBackend(t)
	defer backend.Close()

	// Three scenarios, each sequential so they don't share Caddy state:
	//
	//   legacy       – no delay, close on reload immediately (old default)
	//   close_delay  – stream_close_delay, the old "keep-alive workaround"
	//   retain       – stream_retain_on_reload, the new explicit retain flag
	//
	// Reloads are spread across time and interleaved with echo-checks so
	// stream health is exercised at each reload boundary, not only at the end.
	legacy := runReloadStress(t, tester, backend.addr, "legacy", false, 0)
	closeDelay := runReloadStress(t, tester, backend.addr, "close_delay", false, stressCloseDelay)
	retain := runReloadStress(t, tester, backend.addr, "retain", true, 0)

	if legacy.aliveAfterReloads != 0 {
		t.Fatalf("legacy mode left %d upgraded streams alive after reloads", legacy.aliveAfterReloads)
	}
	if closeDelay.aliveBeforeDelayExpiry == 0 {
		t.Fatalf("close_delay mode: all streams closed before delay expired (expected them alive)")
	}
	if closeDelay.aliveAfterReloads != 0 {
		t.Fatalf("close_delay mode left %d upgraded streams alive after delay expiry", closeDelay.aliveAfterReloads)
	}
	if retain.aliveAfterReloads != retain.streamCount {
		t.Fatalf("retain mode kept %d/%d upgraded streams alive after reloads", retain.aliveAfterReloads, retain.streamCount)
	}

	t.Logf("legacy      heap: before=%s mid=%s after=%s delta(before→after)=%s objects(before=%d after=%d) handler_frames(before=%d after=%d)",
		formatBytes(legacy.beforeReload.HeapInuse),
		formatBytes(legacy.midReload.HeapInuse),
		formatBytes(legacy.afterReload.HeapInuse),
		formatBytesDiff(legacy.beforeReload.HeapInuse, legacy.afterReload.HeapInuse),
		legacy.beforeReload.HeapObjects, legacy.afterReload.HeapObjects,
		legacy.beforeReload.handlerFrames, legacy.afterReload.handlerFrames,
	)
	t.Logf("close_delay heap: before=%s mid=%s after=%s delta(before→after)=%s objects(before=%d after=%d) handler_frames(before=%d after=%d)",
		formatBytes(closeDelay.beforeReload.HeapInuse),
		formatBytes(closeDelay.midReload.HeapInuse),
		formatBytes(closeDelay.afterReload.HeapInuse),
		formatBytesDiff(closeDelay.beforeReload.HeapInuse, closeDelay.afterReload.HeapInuse),
		closeDelay.beforeReload.HeapObjects, closeDelay.afterReload.HeapObjects,
		closeDelay.beforeReload.handlerFrames, closeDelay.afterReload.handlerFrames,
	)
	t.Logf("retain      heap: before=%s mid=%s after=%s delta(before→after)=%s objects(before=%d after=%d) handler_frames(before=%d after=%d)",
		formatBytes(retain.beforeReload.HeapInuse),
		formatBytes(retain.midReload.HeapInuse),
		formatBytes(retain.afterReload.HeapInuse),
		formatBytesDiff(retain.beforeReload.HeapInuse, retain.afterReload.HeapInuse),
		retain.beforeReload.HeapObjects, retain.afterReload.HeapObjects,
		retain.beforeReload.handlerFrames, retain.afterReload.handlerFrames,
	)
}

type stressRunResult struct {
	streamCount           int
	aliveAfterReloads     int
	aliveBeforeDelayExpiry int // only meaningful for close_delay mode
	beforeReload          heapSnapshot
	midReload             heapSnapshot // after all reloads, before delay expiry clean-up
	afterReload           heapSnapshot // after all streams have been fully cleaned up
}

type heapSnapshot struct {
	HeapInuse     uint64
	HeapObjects   uint64
	handlerFrames int
	profileBytes  int
}

// runReloadStress opens streamCount upgraded streams, then performs reloadCount
// config reloads spread over time. An echo check is performed every 6 reloads so
// stream health is exercised at each reload boundary rather than only at the end.
// closeDelay mirrors the stream_close_delay config option; pass 0 to disable.
func runReloadStress(t *testing.T, tester *caddytest.Tester, backendAddr, mode string, retain bool, closeDelay time.Duration) stressRunResult {
	t.Helper()

	const echoEvery = 6 // perform an echo check every N reloads

	streamCount := envIntOrDefault(t, "CADDY_STRESS_STREAM_COUNT", 12)
	reloadCount := envIntOrDefault(t, "CADDY_STRESS_RELOAD_COUNT", 24)

	tester.InitServer(reloadStressConfig(backendAddr, retain, closeDelay, 0), "caddyfile")

	clients := make([]*upgradedStreamClient, 0, streamCount)
	for i := 0; i < streamCount; i++ {
		client := newUpgradedStreamClient(t)
		clients = append(clients, client)
		if err := client.echo(fmt.Sprintf("%s-warmup-%02d\n", mode, i)); err != nil {
			closeClients(clients)
			t.Fatalf("warmup echo failed in %s mode: %v", mode, err)
		}
	}
	defer closeClients(clients)

	before := captureHeapSnapshot(t)

	// Reloads are spread across time; between batches of echoEvery reloads we
	// pause briefly and measure stream health so the snapshot reflects real-world
	// reload cadence rather than a tight loop.
	for i := 1; i <= reloadCount; i++ {
		loadCaddyfileConfig(t, reloadStressConfig(backendAddr, retain, closeDelay, i))

		// Small pause after each reload to let connection teardown propagate.
		time.Sleep(50 * time.Millisecond)

		if i%echoEvery == 0 {
			alive := countAliveStreams(clients)
			t.Logf("%s mode: %d/%d streams alive after reload %d", mode, alive, streamCount, i)

			// In retain mode every stream must survive every reload (upstream unchanged).
			if retain {
				for j, client := range clients {
					if err := client.echo(fmt.Sprintf("%s-mid-%02d-%02d\n", mode, i, j)); err != nil {
						t.Fatalf("retain mode stream %d died at reload %d: %v", j, i, err)
					}
				}
			}
		}
	}

	// mid snapshot: after all reloads but before any close_delay timer has fired
	// (the delay is long enough to still be running at this point).
	mid := captureHeapSnapshot(t)

	// For legacy mode: the reloads close streams immediately; wait for that to complete.
	// For close_delay mode: streams are still alive here; wait for the delay to fire.
	// For retain mode: streams survive indefinitely; no wait needed.
	var aliveBeforeDelayExpiry int
	aliveAfterReloads := countAliveStreams(clients)
	switch {
	case retain:
		// nothing to wait for
	case closeDelay > 0:
		// streams should still be alive at this point (delay hasn't expired)
		aliveBeforeDelayExpiry = aliveAfterReloads
		t.Logf("%s mode: %d/%d streams alive before close_delay expires; waiting %v for cleanup",
			mode, aliveBeforeDelayExpiry, streamCount, closeDelay)
		time.Sleep(closeDelay + 200*time.Millisecond)
		aliveAfterReloads = countAliveStreams(clients)
	default:
		deadline := time.Now().Add(2 * time.Second)
		for aliveAfterReloads > 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			aliveAfterReloads = countAliveStreams(clients)
		}
	}

	after := captureHeapSnapshot(t)
	t.Logf("%s mode heap profile size: before=%dB mid=%dB after=%dB objects(before=%d mid=%d after=%d)",
		mode,
		before.profileBytes, mid.profileBytes, after.profileBytes,
		before.HeapObjects, mid.HeapObjects, after.HeapObjects,
	)

	return stressRunResult{
		streamCount:            streamCount,
		aliveAfterReloads:      aliveAfterReloads,
		aliveBeforeDelayExpiry: aliveBeforeDelayExpiry,
		beforeReload:           before,
		midReload:              mid,
		afterReload:            after,
	}
}

func envIntOrDefault(t *testing.T, key string, def int) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		t.Fatalf("invalid %s=%q: must be a positive integer", key, raw)
	}
	return v
}

func loadCaddyfileConfig(t *testing.T, rawConfig string) {
	t.Helper()

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://localhost:2999/load", strings.NewReader(rawConfig))
	if err != nil {
		t.Fatalf("creating load request: %v", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading load response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loading config failed: status=%d body=%s", resp.StatusCode, body)
	}
}

func reloadStressConfig(backendAddr string, retain bool, closeDelay time.Duration, revision int) string {
	var directives string
	if retain {
		directives += "\n\t\tstream_retain_on_reload"
	}
	if closeDelay > 0 {
		directives += fmt.Sprintf("\n\t\tstream_close_delay %s", closeDelay)
	}

	return fmt.Sprintf(`
{
	admin localhost:2999
	http_port 9080
	https_port 9443
	grace_period 1ns
	skip_install_trust
}

localhost:9080 {
	reverse_proxy %s {
		header_up X-Reload-Revision %d%s
	}
}
`, backendAddr, revision, directives)
}

func captureHeapSnapshot(t *testing.T) heapSnapshot {
	t.Helper()

	runtime.GC()
	debug.FreeOSMemory()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var buf bytes.Buffer
	if err := pprof.Lookup("heap").WriteTo(&buf, 1); err != nil {
		t.Fatalf("capturing heap profile: %v", err)
	}
	profile := buf.String()

	return heapSnapshot{
		HeapInuse:     mem.HeapInuse,
		HeapObjects:   mem.HeapObjects,
		handlerFrames: strings.Count(profile, "modules/caddyhttp/reverseproxy.(*Handler)"),
		profileBytes:  buf.Len(),
	}
}

func countAliveStreams(clients []*upgradedStreamClient) int {
	alive := 0
	for index, client := range clients {
		if err := client.echo(fmt.Sprintf("alive-check-%02d\n", index)); err == nil {
			alive++
		}
	}
	return alive
}

func closeClients(clients []*upgradedStreamClient) {
	for _, client := range clients {
		if client != nil {
			_ = client.Close()
		}
	}
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatBytesDiff(before, after uint64) string {
	if after >= before {
		return "+" + formatBytes(after-before)
	}
	return "-" + formatBytes(before-after)
}

type upgradedStreamClient struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
}

func newUpgradedStreamClient(t *testing.T) *upgradedStreamClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", "127.0.0.1:9080", 5*time.Second)
	if err != nil {
		t.Fatalf("dialing caddy: %v", err)
	}

	request := strings.Join([]string{
		"GET /upgrade HTTP/1.1",
		"Host: localhost:9080",
		"Connection: Upgrade",
		"Upgrade: stress-stream",
		"",
		"",
	}, "\r\n")
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		t.Fatalf("writing upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	tproto := textproto.NewReader(reader)
	statusLine, err := tproto.ReadLine()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("reading upgrade status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		t.Fatalf("unexpected upgrade status: %s", statusLine)
	}

	headers, err := tproto.ReadMIMEHeader()
	if err != nil {
		_ = conn.Close()
		t.Fatalf("reading upgrade headers: %v", err)
	}
	if !strings.EqualFold(headers.Get("Connection"), "Upgrade") {
		_ = conn.Close()
		t.Fatalf("unexpected upgrade response headers: %v", headers)
	}

	return &upgradedStreamClient{conn: conn, reader: reader}
}

func (c *upgradedStreamClient) echo(payload string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Now().Add(1 * time.Second)
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(c.conn, payload); err != nil {
		return err
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return err
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c.reader, buf); err != nil {
		return err
	}
	if string(buf) != payload {
		return fmt.Errorf("unexpected echoed payload: got %q want %q", string(buf), payload)
	}
	return nil
}

func (c *upgradedStreamClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

type upgradeEchoBackend struct {
	addr   string
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	server *http.Server
}

func newUpgradeEchoBackend(t *testing.T) *upgradeEchoBackend {
	t.Helper()

	backend := &upgradeEchoBackend{conns: make(map[net.Conn]struct{})}
	backend.server = &http.Server{
		Handler: http.HandlerFunc(backend.serveHTTP),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for backend: %v", err)
	}
	backend.ln = ln
	backend.addr = ln.Addr().String()

	go func() {
		_ = backend.server.Serve(ln)
	}()

	return backend
}

func (b *upgradeEchoBackend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "stress-stream") {
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

	b.trackConn(conn)
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: stress-stream\r\n\r\n")
	_ = rw.Flush()

	go func() {
		defer b.untrackConn(conn)
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
}

func (b *upgradeEchoBackend) trackConn(conn net.Conn) {
	b.mu.Lock()
	b.conns[conn] = struct{}{}
	b.mu.Unlock()
}

func (b *upgradeEchoBackend) untrackConn(conn net.Conn) {
	b.mu.Lock()
	delete(b.conns, conn)
	b.mu.Unlock()
}

func (b *upgradeEchoBackend) Close() {
	_ = b.server.Close()
	_ = b.ln.Close()

	b.mu.Lock()
	defer b.mu.Unlock()
	for conn := range b.conns {
		_ = conn.Close()
	}
	clear(b.conns)
}
