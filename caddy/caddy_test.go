package caddy

import (
	"net/http"
	"testing"
	"time"

	"github.com/mholt/caddy/caddy/https"
	"github.com/xenolf/lego/acme"
)

func TestCaddyStartStop(t *testing.T) {
	// Use fake ACME clients for testing
	https.NewACMEClient = func(email string, allowPrompts bool) (*https.ACMEClient, error) {
		return &https.ACMEClient{
			Client:       new(acme.Client),
			AllowPrompts: allowPrompts,
		}, nil
	}

	caddyfile := "localhost:1984"

	for i := 0; i < 2; i++ {
		err := Start(CaddyfileInput{Contents: []byte(caddyfile)})
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
