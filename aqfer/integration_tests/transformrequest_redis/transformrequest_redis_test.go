package tests

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	. ".."
)

var client *http.Client
var url string

func init() {
	client = &http.Client{}
	url = "http://localhost:8082"
}

func run(method, path, status string, t *testing.T) *http.Response {
	req, err := http.NewRequest(method, url+path, nil)
	if err != nil {
		t.Log(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Log(err)
	}

	if !strings.Contains(resp.Status, status) {
		t.Errorf("Unexpected Status: `%s`", resp.Status)
	}

	return resp
}

func TestIntegrationOftransformrequestWithRedis(t *testing.T) {
	fmt.Println("-----TestIntegrationOfTransformrequestWithRedis-----")

	// Cleanup()
	RunDocker()
	time.Sleep(20 * time.Second)

	t.Log("Testing request with missing path params")
	run("GET", "/test.go", "400", t)

	// return

	path := "/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf/test.go"

	t.Log("Testing request with path params, and missing security context")
	run("GET", path, "403", t)

	t.Log("Testing request with path params and security context, but wrong cid")
	run("GET", path+"?security_context={\"scope\":{\"cids\":[\"fdsa\"]}}", "403", t)

	securityContext := "security_context={\"scope\":{\"cids\":[\"asdf\"]}}"

	t.Log("Testing request with path params and security context to allowed cid, on missing redis key")
	run("GET", path+"?"+securityContext, "404", t)

	t.Log("Testing PUT with no values into missing redis key")
	run("PUT", path+"?"+securityContext, "201", t)

	t.Log("Testing GET of exisiting key")
	run("GET", path+"?"+securityContext, "200", t)

	// redis module only passes on execution on a 200, so no longer need for a file at end of path
	path = "/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf"

	t.Log("Testing PUT non list value into existing redis key")
	run("PUT", path+"?"+securityContext+"&value=asdf", "204", t)

	t.Log("Testing PUT with different types of values on existing key over existing value")
	run("PUT", path+"?"+securityContext+"&value=qwer&firstlist=[asdf,fdsa]&number=1", "204", t)

	t.Log("Testing POST of list to exisiting key")
	run("POST", path+"?"+securityContext+"&list=[]", "204", t)

	t.Log("Testing POST prepend to non exisiting key")
	run("POST", path+"?"+securityContext+"&list2=$PREPEND(a)", "204", t)

	t.Log("Testing POST append to exisiting key")
	run("POST", path+"?"+securityContext+"&list2=$APPEND(b)", "204", t)

	t.Log("Testing POST prepend to non list key")
	run("POST", path+"?"+securityContext+"&value=$PREPEND(b)", "409", t)

	t.Log("Testing POST incr to non number value")
	run("POST", path+"?"+securityContext+"&value=$INCR", "409", t)

	t.Log("Testing POST add to non number value")
	run("POST", path+"?"+securityContext+"&value=$ADD(1.2)", "409", t)

	t.Log("Testing POST value on existing key to replace")
	run("POST", path+"?"+securityContext+"&value=1", "204", t)

	t.Log("Testing POST incr to number value")
	run("POST", path+"?"+securityContext+"&value=$INCR", "204", t)

	t.Log("Testing POST add to number value")
	run("POST", path+"?"+securityContext+"&value=$ADD(1.2)", "204", t)

	t.Log("Testing POST append to non list key")
	run("POST", path+"?"+securityContext+"&value=$APPEND(b)", "409", t)

	t.Log("Testing POST delete to key")
	run("POST", path+"?"+securityContext+"&list2=$DELETE", "204", t)

	t.Log("Testing POST append to non exisiting key")
	run("POST", path+"?"+securityContext+"&list2=$APPEND(a)", "204", t)

	t.Log("Testing POST multiple commands to same key")
	run("POST", path+"?"+securityContext+"&list2=$APPEND(a)&list2=$INCR", "400", t)

	t.Log("Testing POST incr to list value")
	run("POST", path+"?"+securityContext+"&list=$INCR", "409", t)

	t.Log("Testing POST add to list value")
	run("POST", path+"?"+securityContext+"&list=$ADD(1.2)", "409", t)

	t.Log("Testing POST incr to non existent key")
	run("POST", path+"?"+securityContext+"&value2=$INCR", "204", t)

	t.Log("Testing POST add non existent key")
	run("POST", path+"?"+securityContext+"&value3=$ADD(1.2)", "204", t)

	t.Log("Testing POST incr to value with bad syntax")
	run("POST", path+"?"+securityContext+"&value2=$INCR(1.2)", "400", t)

	t.Log("Testing POST add to value with bad syntax")
	run("POST", path+"?"+securityContext+"&value2=$ADD", "400", t)

	t.Log("Testing DELETE to non existent key")
	run("DELETE", path+"?"+securityContext+"&value3=asdf", "204", t)

	t.Log("Testing DELETE to existent key")
	run("DELETE", path+"?"+securityContext+"&value3=asdf", "204", t)

	Cleanup()
}
