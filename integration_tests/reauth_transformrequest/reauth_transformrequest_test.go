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

func TestIntegrationOfReauthWithTransformrequest(t *testing.T) {
	fmt.Println("-----TestIntegrationOfReauthWithTransformrequest-----")

	RunDocker()
	time.Sleep(10 * time.Second)

	client := &http.Client{}

	t.Log("Testing request to secured path missing path params")
	req, err := http.NewRequest("GET", "http://localhost:8082/ids/v1/test.go", nil)
	if err != nil {
		t.Log(err)
	}

	clientToken := GetTokenWithRefresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDg4Njk2OTMsImp0aSI6ImUxNjBjOTI2LTA1ZTMtMTFlOC05ZTVlLTBlNmQ0Y2U3MDRhYSIsImlhdCI6MTUxNzMzMzY5MywidXNlciI6IkFsZnJlZG8iLCJlbWFpbCI6ImFsZnJlZG9AY2xvdWRzcGFjZS5jb20iLCJzY29wZSI6eyJjaWRzIjpbImMwMDkiXX0sInR5cGUiOiJyZWZyZXNoX3Rva2VuIiwicm9sZXMiOlsiY2xpZW50X3VzZXIiLCJhY2Nlc3NfdG9rZW5fdmFsaWRhdG9yIl19.nLcVQSQSuz_FSdJkpVKJ-uNQHjuG_gCNQmuIF7_ApCE")
	req.Header.Set("Authorization", "Bearer "+clientToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Log(err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
	}
	if !strings.Contains(resp.Status, "400") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request to secured path with proper params but wrong cid")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/c008/asdf/asdf/asdf/test.go", nil)
	if err != nil {
		t.Log(err)
	}
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
	if !strings.Contains(resp.Status, "403") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request to secured path with proper path params")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/c009/asdf/asdf/asdf/test.go", nil)
	if err != nil {
		t.Log(err)
	}
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
