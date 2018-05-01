package tests

import (
	"encoding/json"
	"fmt"
	. "github.com/startsmartlabs/caddy/integration_tests"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

var client *http.Client
var url string
var clientToken string

func init() {
	client = &http.Client{}
	clientToken = GetTokenWithRefresh("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTI0ODg5OTgsImp0aSI6ImJiOTk0NGYwLTI2Y2UtMTFlOC05MTNlLTI2MDA4Mjg4MjhiZCIsImlhdCI6MTUyMDk1Mjk5OCwidXNlciI6IkFsZnJlZG8iLCJlbWFpbCI6ImFsZnJlZG9AY2xvdWRzcGFjZS5jb20iLCJzY29wZSI6eyJjaWRzIjpbImMwMDkiXX0sInR5cGUiOiJyZWZyZXNoX3Rva2VuIiwicm9sZXMiOlsiY2xpZW50X3VzZXIiLCJhY2Nlc3NfdG9rZW5fdmFsaWRhdG9yIl19.eosrelW4c-20gv-mhZ_To8GLojEcasJG_fibwTsntLc")
	url = "http://localhost:8082"
}

func run(method, path, status string, t *testing.T) *http.Response {
	req, err := http.NewRequest(method, url+path, nil)
	req.Header.Set("Authorization", "Bearer "+clientToken)
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

func TestFullStack(t *testing.T) {
	fmt.Println("-----TestFullStack-----")

	RunDocker()
	time.Sleep(20 * time.Second)

	path := "/v1/cids/c009/entity_types/asdf/domains/asdf/keys/asdf"

	t.Log("GET on non existent key")
	run("GET", path, "404", t)

	// PUT tests
	t.Log("PUT with no values")
	run("PUT", path, "201", t)
	resp := run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["last_update"].S == "" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT with non list value")
	run("PUT", path+"?value=asdf", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}

		if (*data)["value"].S != "asdf" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value")
	run("PUT", path+"?value=asdf", "204", t)
	run("PUT", path+"?value=fdsa", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "fdsa" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value with empty list")
	run("PUT", path+"?value=asdf", "204", t)
	run("PUT", path+"?value=[]", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S == "fdsa" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["value"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		}
	}

	t.Log("PUT replace value with number")
	run("PUT", path+"?value=asdf", "204", t)
	run("PUT", path+"?value=12", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "12" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value with non empty list")
	run("PUT", path+"?value=asdf", "204", t)
	run("PUT", path+"?value=[a,b,c]", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S == "12" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["value"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			if len((*data)["value"].Sl) != 3 {
				t.Errorf("Expected entity to have list of three items, had: `%d`", len((*data)["value"].Sl))
			}
		}
	}

	t.Log("PUT escaped strings")
	run("PUT", path+"?space=y+e%20s&math=%25%26%2B%2C%3D%5D%5B", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["math"].S != "%&+,=][" || (*data)["space"].S != "y e s" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT multiple value types overwriting existing ones and adding list with empty strings")
	run("PUT", path+"?value=asdf&math=0", "204", t)
	run("PUT", path+"?value=thing&math=1&list=[a,b,,c,]", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "thing" || (*data)["math"].S != "1" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			if len((*data)["list"].Sl) != 5 {
				t.Errorf("Expected entity to have list of three items, had: `%d`", len((*data)["list"].Sl))
			}
		}
	}

	// POST tests

	t.Log("POST multiple value types overwriting existing ones")
	run("PUT", path+"?value=asdf&math=0&list=[1,2,3]", "204", t)
	run("POST", path+"?value=other&math=2.3&list=[a,,b,]", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "other" || (*data)["math"].S != "2.3" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			if len((*data)["list"].Sl) != 4 {
				t.Errorf("Expected entity to have list of three items, had: `%d`", len((*data)["list"].Sl))
			}
		}
	}

	t.Log("POST delete action on non list attribute, add on number attribute, append on list attribute")
	run("PUT", path+"?value=asdf&math=0&list=[a,,b,]", "204", t)
	run("POST", path+"?value=$DELETE&math=$ADD(1.7)&list=$APPEND(c,d)", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "" || (*data)["math"].S[0:3] != "1.7" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			valueList := (*data)["list"].Sl
			if len(valueList) != 6 {
				t.Errorf("Expected entity to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" || valueList[4] != "c" || valueList[5] != "d" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST new value to non list attribute, add one to number attribute, append on list attribute")
	run("PUT", path+"?value=asdf&math=4&list=[a,,b,]", "204", t)
	run("POST", path+"?value=new&math=$INCR&list=$PREPEND(-2,-1,0,)", "204", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "new" || (*data)["math"].S[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			if len((*data)["list"].Sl) != 8 {
				t.Errorf("Expected entity to have list of eight items, had: `%d`", len((*data)["list"].Sl))
			}
			valueList := (*data)["list"].Sl
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of append on non list item")
	run("PUT", path+"?value=asdf&math=1.6&list=[a,,b,]", "204", t)
	run("POST", path+"?value=$APPEND(wrong)&math=$ADD(3.4)&list=$PREPEND(-2,-1,0,)", "409", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["math"].S[0:3] != "1.6" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			valueList := (*data)["list"].Sl
			if len(valueList) != 4 {
				t.Errorf("Expected entity to have list of four items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of prepend on non list item")
	run("PUT", path+"?value=asdf&math=1.6&list=[a,,b,]", "204", t)
	run("POST", path+"?value=$PREPEND(wrong)&math=$INCR&list=$PREPEND(-2,-1,0,)", "409", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "asdf" || (*data)["math"].S[0:3] != "1.6" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			valueList := (*data)["list"].Sl
			if len(valueList) != 4 {
				t.Errorf("Expected entity to have list of four items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of INCR on non num item")
	run("PUT", path+"?value=asdf&math=1.6&list=[a,,b,]", "204", t)
	run("POST", path+"?value=$INCR&math=$INCR&list=$PREPEND(-2,-1,0)", "409", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "asdf" || (*data)["math"].S[0:3] != "1.6" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			valueList := (*data)["list"].Sl
			if len(valueList) != 4 {
				t.Errorf("Expected entity to have list of four items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of ADD on non num item")
	run("PUT", path+"?value=asdf&math=1.6&list=[a,,b,]", "204", t)
	run("POST", path+"?value=$ADD(1.2)&math=$ADD(2.3)&list=$APPEND(e,f,)", "409", t)
	resp = run("GET", path, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if (*data)["value"].S != "asdf" || (*data)["math"].S[0:3] != "1.6" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if (*data)["list"].Sl == nil {
			t.Errorf("Expected entity to contain list, got: nil")
		} else {
			valueList := (*data)["list"].Sl
			if len(valueList) != 4 {
				t.Errorf("Expected entity to have list of four items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	// DELETE tests

	t.Log("DELETE")
	run("DELETE", path, "204", t)
	run("GET", path, "404", t)

	Cleanup()
}

type Entity map[string]AttributeValue

type AttributeValue struct {
	AttributeType AttributeType
	S             string
	Sl            []string
}

type AttributeType int
