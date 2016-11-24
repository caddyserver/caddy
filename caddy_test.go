package caddy

import (
	"net"
	"testing"
)

/*
// TODO
func TestCaddyStartStop(t *testing.T) {
	caddyfile := "localhost:1984"

	for i := 0; i < 2; i++ {
		_, err := Start(CaddyfileInput{Contents: []byte(caddyfile)})
		if err != nil {
			t.Fatalf("Error starting, iteration %d: %v", i, err)
		}

		client := http.Client{
			Timeout: time.Duration(2 * time.Second),
		}
		resp, err := client.Get("http://localhost:1984")
		if err != nil {
			t.Fatalf("Expected GET request to succeed (iteration %d), but it failed: %v", i, err)
		}
		resp.Body.Close()

		err = Stop()
		if err != nil {
			t.Fatalf("Error stopping, iteration %d: %v", i, err)
		}
	}
}
*/

func TestIsLoopback(t *testing.T) {
	for i, test := range []struct {
		input  string
		expect bool
	}{
		{"example.com", false},
		{"localhost", true},
		{"localhost:1234", true},
		{"localhost:", true},
		{"127.0.0.1", true},
		{"127.0.0.1:443", true},
		{"127.0.1.5", true},
		{"10.0.0.5", false},
		{"12.7.0.1", false},
		{"[::1]", true},
		{"[::1]:1234", true},
		{"::1", true},
		{"::", false},
		{"[::]", false},
		{"local", false},
	} {
		if got, want := IsLoopback(test.input), test.expect; got != want {
			t.Errorf("Test %d (%s): expected %v but was %v", i, test.input, want, got)
		}
	}
}

func TestListenerAddrEqual(t *testing.T) {
	ln1, err := newLocalListener("[::]:2016")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()

	ln2, err := newLocalListener("[::]:2017")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	for i, test := range []struct {
		ln     net.Listener
		addr   string
		expect bool
	}{
		{ln1, "0.0.0.0:2016", true},
		{ln2, "0.0.0.0:2018", false},
	} {
		if got, want := listenerAddrEqual(test.ln, test.addr), test.expect; got != want {
			t.Errorf("Test %d (%v == %v): expected %v but was %v", i, test.addr, test.ln.Addr().String(), want, got)
		}
	}
}

func newLocalListener(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return ln, nil
}
