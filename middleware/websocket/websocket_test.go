package websocket

import (
	"net/http"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatal("Error setting up request:", err)
	}
	req.RemoteAddr = "localhost:50302"

	env, err := buildEnv("/bin/command", req)
	if err != nil {
		t.Fatal("Didn't expect an error:", err)
	}
	if len(env) == 0 {
		t.Fatalf("Expected non-empty environment; got %#v", env)
	}
}
