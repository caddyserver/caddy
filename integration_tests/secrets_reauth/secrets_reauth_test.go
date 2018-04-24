package tests

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	. ".."
)

func TestIntegrationOfSecretsWithReauth(t *testing.T) {
	fmt.Println("-----TestIntegrationOfSecretsWithReauth-----")

	RunDocker()
	time.Sleep(10 * time.Second)

	client := &http.Client{}

	t.Log("Testing request to unsecured path")
	req, err := http.NewRequest("GET", "http://localhost:8082/main.go", nil)
	if err != nil {
		t.Log(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Log(err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
	}
	if !strings.Contains(resp.Status, "200") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request to secured path with no credentials")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/main.go", nil)
	if err != nil {
		t.Log(err)
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Log(err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
	}
	if !strings.Contains(resp.Status, "401") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request to secured path with credentials including secrets file")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/main.go", nil)
	if err != nil {
		t.Log(err)
	}

	// clientToken in request, refreshToken pulled from secrets file
	clientToken := GetTokenWithRefresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDg4Njk2OTMsImp0aSI6ImUxNjBjOTI2LTA1ZTMtMTFlOC05ZTVlLTBlNmQ0Y2U3MDRhYSIsImlhdCI6MTUxNzMzMzY5MywidXNlciI6IkFsZnJlZG8iLCJlbWFpbCI6ImFsZnJlZG9AY2xvdWRzcGFjZS5jb20iLCJzY29wZSI6eyJjaWRzIjpbImMwMDkiXX0sInR5cGUiOiJyZWZyZXNoX3Rva2VuIiwicm9sZXMiOlsiY2xpZW50X3VzZXIiLCJhY2Nlc3NfdG9rZW5fdmFsaWRhdG9yIl19.nLcVQSQSuz_FSdJkpVKJ-uNQHjuG_gCNQmuIF7_ApCE")
	req.Header.Set("Authorization", "Bearer "+clientToken)

	resp, err = client.Do(req)
	if err != nil {
		t.Log(err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
	}
	if !strings.Contains(resp.Status, "200") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	Cleanup()
}
