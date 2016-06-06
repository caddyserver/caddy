package caddy

import "testing"

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
