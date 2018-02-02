package tests

import (
	"fmt"
	//"io/ioutil"
	"strings"
	"testing"

	transformrequest ".."
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"net/http/httptest"
)

func init() {
}

func TestTransformrequestSetup(t *testing.T) {
	fmt.Println("-----TestTransformrequestSetup-----")

	c := caddy.NewTestController("http", "")
	err := transformrequest.Setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	cfg := httpserver.GetConfig(c)
	mids := cfg.Middleware()
	if len(mids) > 0 {
		t.Error("Exptected setup to have failed")
	}

	c = caddy.NewTestController("http", "transformrequest")
	err = transformrequest.Setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	cfg = httpserver.GetConfig(c)
	mids = cfg.Middleware()
	myHandler := mids[0](httpserver.EmptyNext)
	_, ok := myHandler.(*transformrequest.TransformrequestHandler)
	if !ok {
		t.Errorf("Expected transformrequest.TransformrequestHandler, got %T", myHandler)
	}

	c = caddy.NewTestController("http", "transformrequest something")
	err = transformrequest.Setup(c)
	if err == nil {
		t.Error("Expected error `TransformRequest received more arguments than expected`")
	}
}

// func TestHandler(t *testing.T) {
// 	fmt.Println("-----TestHandler-----")
// }

func TestRedisFuncValidity(t *testing.T) {
	fmt.Println("-----TestRedisFuncValidity-----")

	c := caddy.NewTestController("http", "transformrequest")
	transformrequest.Setup(c)
	cfg := httpserver.GetConfig(c)
	mids := cfg.Middleware()
	myHandler := mids[0](httpserver.EmptyNext).(*transformrequest.TransformrequestHandler)

	writer := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://www.example.com", nil)
	status, err := (*myHandler).ServeHTTP(writer, request)
	if err == nil {
		t.Error("Expected error `Missing path parameters`")
	}
	if status != 400 {
		t.Error("Expected Bad Request because of missing parameters")
	}

	request = httptest.NewRequest("GET", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf", nil)
	status, err = (*myHandler).ServeHTTP(writer, request)
	if err == nil {
		t.Error("Expected error `Security Context missing, Cid access can't be authenticated`")
	}
	if status != 403 {
		t.Error("Expected Forbidden because of missing security context")
	}

	request = httptest.NewRequest("GET", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context={}", nil)
	status, err = (*myHandler).ServeHTTP(writer, request)
	if err == nil {
		t.Error("Expected error `Cid not allowed for this user`")
	}
	if status != 403 {
		t.Error("Expected Forbidden because request cid didn't match security context scope cids")
	}

	securityContext := "{\"scope\":{\"cids\":[\"asdf\"]}}"
	request = httptest.NewRequest("GET", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/sadf/keys/asdf?security_context="+securityContext, nil)
	status, err = (*myHandler).ServeHTTP(writer, request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}

	request = httptest.NewRequest("GET", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext, nil)
	_, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
}

func TestRedisFuncTransformations(t *testing.T) {
	fmt.Println("-----TestRedisFuncTransformations-----")

	securityContext := "{\"scope\":{\"cids\":[\"asdf\"]}}"

	t.Log("Testing GET request")
	request := httptest.NewRequest("GET", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext, nil)
	transformed, err := transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["GETALL"][0] != "asdf:asdf:asdf:asdf" {
		t.Error("Unexpected transformation")
	}

	// PUT TESTS

	t.Log("Testing PUT request with no attributes")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext, nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with non list item")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&test=something", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs test something last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with one list with no items")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with one list with one item")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=something,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:list something" ||
		!strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with one list with more than one item")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=something,else,and,another,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:list something else and another" ||
		!strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with more than one list")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list1=thing1,&list2=thing2,thing3,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["RPUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with more than one list a couple empty")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list0=,&list1=thing1,&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["RPUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with lists and nonlist attribute")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["RPUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs something else last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PUT request with lists and more than one nonlist attributes")
	request = httptest.NewRequest("PUT", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["RPUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs something else another now last_update ") &&
		!strings.Contains(transformed.Form["HMSET"][0], "asdf:asdf:asdf:asdf:kvs another now something else last_update ") {
		t.Error("Unexpected transformation")
	}

	// PATCH TESTS

	t.Log("Testing PATCH request with no attributes")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext, nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with non list item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&test=something", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["HSET"][0] != "asdf:asdf:asdf:asdf:kvs test something" ||
		!strings.Contains(transformed.Form["HSET"][1], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with one list with no items")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with one list with one item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=thing,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["PUSH"][0] != "asdf:asdf:asdf:asdf:list thing" {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with one list with more than one item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list=something,else,and,another,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if transformed.Form["PUSH"][0] != "asdf:asdf:asdf:asdf:list something else and another" {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with more than one list")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list1=thing1,&list2=thing2,thing3,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with more than one list a couple empty")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&list0=,&list1=thing1,&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !strings.Contains(transformed.Form["HSET"][0], "asdf:asdf:asdf:asdf:kvs last_update ") {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists and nonlist attribute")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists and more than one nonlist attributes")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, and DELETE")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&del=$DELETE", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request DELETE with parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&del=$DELETE(this)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, and INCR")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request INCR with parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&inc=$INCR(1.2)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL and INCR")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, and PREPEND")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&pre=$PREPEND(pend)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["LPUSH"], []string{"asdf:asdf:asdf:asdf:pre pend"}) {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, and PREPEND more than one item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&pre=$PREPEND(pend,things,here)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["LPUSH"], []string{"asdf:asdf:asdf:asdf:pre pend things here"}) {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request PREPEND with no parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&float=$PREPEND", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, and APPEND")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&app=$APPEND(end)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:app end" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, and APPEND more than one item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&app=$APPEND(end,things,there)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:app end things there" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request APPEND with no parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&float=$APPEND", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, PREPEND and APPEND more than one item")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&app=$APPEND(end,things,there)&pre=$PREPEND(pend,things,here)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:app end things there" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["LPUSH"][0] != "asdf:asdf:asdf:asdf:pre pend things here" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request with lists, nonlist attributes, DEL, INCR, PREPEND and APPEND more than one item, and ADD decimal")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&something=else&list0=,&list1=thing1,&another=now&list2=thing2,thing3,&list3=,&inc=$INCR&del=$DELETE&app=$APPEND(end,things,there)&pre=$PREPEND(pend,things,here)&float=$ADD(1.2)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	transformed.ParseForm()
	fmt.Println(transformed.Form)
	if !includes(transformed.Form["PUSH"], []string{"asdf:asdf:asdf:asdf:list1 thing1", "asdf:asdf:asdf:asdf:list2 thing2 thing3"}) {
		t.Error("Unexpected transformation")
	}
	if !includes(transformed.Form["HSET"], []string{"asdf:asdf:asdf:asdf:kvs something else", "asdf:asdf:asdf:asdf:kvs another now", "asdf:asdf:asdf:asdf:kvs last_update "}) {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HDEL"][0] != "asdf:asdf:asdf:asdf:kvs del" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBY"][0] != "asdf:asdf:asdf:asdf:kvs inc 1" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["RPUSH"][0] != "asdf:asdf:asdf:asdf:app end things there" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["LPUSH"][0] != "asdf:asdf:asdf:asdf:pre pend things here" {
		t.Error("Unexpected transformation")
	}
	if transformed.Form["HINCRBYFLOAT"][0] != "asdf:asdf:asdf:asdf:kvs float 1.2" {
		t.Error("Unexpected transformation")
	}

	t.Log("Testing PATCH request ADD with no parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&float=$ADD", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with non decimal ADD")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&float=$ADD(not)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `ADD value was not a float`")
	}

	t.Log("Testing PATCH request with unknown command with parenthesis")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&do=$SOMETHING(not)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with unknown command")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&do=$SOMETHING(not)", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with no command but bad key")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&do-not-do=thing", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err == nil {
		t.Error("Expected error `Could not parse request`")
	}

	t.Log("Testing PATCH request with acceptable key")
	request = httptest.NewRequest("PATCH", "http://www.example.com/ids/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf?security_context="+securityContext+"&Do_A=Thing", nil)
	transformed, err = transformrequest.Functions["redis"].Transform(request)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
}

func includes(inArray, toFind []string) bool {
	included := 0
	for _, in := range inArray {
		for _, to := range toFind {
			if strings.Contains(in, to) {
				included++
				break
			}
		}
	}
	return included == len(toFind)
}
