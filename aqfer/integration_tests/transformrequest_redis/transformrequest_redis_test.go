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

func TestIntegrationOftransformrequestWithRedis(t *testing.T) {
	fmt.Println("-----TestIntegrationOfTransformrequestWithRedis-----")

	RunDocker()
	time.Sleep(5 * time.Second)

	client := &http.Client{}

	t.Log("Testing request with missing path params")
	req, err := http.NewRequest("GET", "http://localhost:8082/test.go", nil)
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
	if !strings.Contains(resp.Status, "400") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params, and missing security context")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go", nil)
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
	if !strings.Contains(resp.Status, "403") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params and security context, but wrong cid")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go?security_context={}", nil)
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
	if !strings.Contains(resp.Status, "403") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params and security context to allowed cid, on missing redis key")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go?security_context={\"scope\":{\"cids\":[\"asdf\"]}}", nil)
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
	if !strings.Contains(resp.Status, "404") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params and security context to allowed cid, with no values to PUT into redis")
	req, err = http.NewRequest("PUT", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go?security_context={\"scope\":{\"cids\":[\"asdf\"]}}", nil)
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
	if !strings.Contains(resp.Status, "400") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params and security context to allowed cid, with values to PUT into redis")
	req, err = http.NewRequest("PUT", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go?security_context={\"scope\":{\"cids\":[\"asdf\"]}}&values=asdf", nil)
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
	if !strings.Contains(resp.Status, "200") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	t.Log("Testing request with path params and security context to allowed cid, on existing redis key")
	req, err = http.NewRequest("GET", "http://localhost:8082/ids/v1/asdf/asdf/asdf/asdf/test.go?security_context={\"scope\":{\"cids\":[\"asdf\"]}}", nil)
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
	if !strings.Contains(resp.Status, "200") {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	Cleanup()
}
