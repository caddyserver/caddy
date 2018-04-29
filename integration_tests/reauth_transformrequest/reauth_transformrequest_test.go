package tests

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	. "github.com/startsmartlabs/caddy/integration_tests"
)

func TestIntegrationOfReauthWithTransformrequest(t *testing.T) {
	fmt.Println("-----TestIntegrationOfReauthWithTransformrequest-----")

	RunDocker()
	time.Sleep(10 * time.Second)

	client := &http.Client{}
	clientToken := GetTokenWithRefresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTI0ODg5OTgsImp0aSI6ImJiOTk0NGYwLTI2Y2UtMTFlOC05MTNlLTI2MDA4Mjg4MjhiZCIsImlhdCI6MTUyMDk1Mjk5OCwidXNlciI6IkFsZnJlZG8iLCJlbWFpbCI6ImFsZnJlZG9AY2xvdWRzcGFjZS5jb20iLCJzY29wZSI6eyJjaWRzIjpbImMwMDkiXX0sInR5cGUiOiJyZWZyZXNoX3Rva2VuIiwicm9sZXMiOlsiY2xpZW50X3VzZXIiLCJhY2Nlc3NfdG9rZW5fdmFsaWRhdG9yIl19.eosrelW4c-20gv-mhZ_To8GLojEcasJG_fibwTsntLc")

	t.Log("Testing request to secured path missing path params")
	req, err := http.NewRequest("GET", "http://localhost:8082/v1/main.go", nil)
	if err != nil {
		t.Log(err)
	}
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
	req, err = http.NewRequest("GET", "http://localhost:8082/v1/cids/c008/entity_types/asdf/domains/asdf/keys/asdf/main.go", nil)
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
	req, err = http.NewRequest("GET", "http://localhost:8082/v1/cids/c009/entity_types/asdf/domains/asdf/keys/asdf/main.go", nil)
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
