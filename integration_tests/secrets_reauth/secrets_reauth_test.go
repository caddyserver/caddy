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
	req, err = http.NewRequest("GET", "http://localhost:8082/v1/main.go", nil)
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

	// TODO: update to 401 after https://github.com/freman/caddy-reauth/pull/12 goes through,
	// at the moment, caddy-reauth is a bit to strict on missing headers. Alfredo Uribe (04/27/2018)
	//
	// if !strings.Contains(resp.Status, "401") {
	if !strings.Contains(resp.Status, "500") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request to secured path with credentials including secrets file")
	req, err = http.NewRequest("GET", "http://localhost:8082/v1/main.go", nil)
	if err != nil {
		t.Log(err)
	}

	// clientToken in request, refreshToken pulled from secrets file
	clientToken := GetTokenWithRefresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTI0ODg5OTgsImp0aSI6ImJiOTk0NGYwLTI2Y2UtMTFlOC05MTNlLTI2MDA4Mjg4MjhiZCIsImlhdCI6MTUyMDk1Mjk5OCwidXNlciI6IkFsZnJlZG8iLCJlbWFpbCI6ImFsZnJlZG9AY2xvdWRzcGFjZS5jb20iLCJzY29wZSI6eyJjaWRzIjpbImMwMDkiXX0sInR5cGUiOiJyZWZyZXNoX3Rva2VuIiwicm9sZXMiOlsiY2xpZW50X3VzZXIiLCJhY2Nlc3NfdG9rZW5fdmFsaWRhdG9yIl19.eosrelW4c-20gv-mhZ_To8GLojEcasJG_fibwTsntLc")
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
