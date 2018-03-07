package tests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

func TestFullStack(t *testing.T) {
	fmt.Println("-----TestFullStack-----")

	RunDocker()
	time.Sleep(10 * time.Second)

	path := "/v1/cids/asdf/entity_types/asdf/domains/asdf/keys/asdf"
	securityContext := "security_context={\"scope\":{\"cids\":[\"asdf\"]}}"

	t.Log("GET on non existent key")
	run("GET", path+"?"+securityContext, "404", t)

	// return

	// PUT tests
	t.Log("PUT with no values")
	run("PUT", path+"?"+securityContext, "201", t)
	resp := run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || len(data.Attributes) != 0 {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT with non list value")
	run("PUT", path+"?"+securityContext+"&value=asdf", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "asdf" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value")
	run("PUT", path+"?"+securityContext+"&value=fdsa", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "fdsa" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value with empty list")
	run("PUT", path+"?"+securityContext+"&value=[]", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if _, ok := data.Attributes["value"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		}
	}

	t.Log("PUT replace value with number")
	run("PUT", path+"?"+securityContext+"&value=12", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "12" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT replace value with non empty list")
	run("PUT", path+"?"+securityContext+"&value=[a,b,c]", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["value"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 3 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
		}
	}

	t.Log("PUT escaped strings")
	run("PUT", path+"?"+securityContext+"&space=y+e%20s&math=%25%26%2B%2C%3D%5D%5B", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["math"] != "%&+,=][" || data.Attributes["space"] != "y e s" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
	}

	t.Log("PUT multiple value types overwriting existing ones and adding list with empty strings")
	run("PUT", path+"?"+securityContext+"&value=thing&math=1&list=[a,b,,c,]", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "thing" || data.Attributes["math"] != "1" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 5 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
		}
	}

	// POST tests

	t.Log("POST multiple value types overwriting existing ones")
	run("POST", path+"?"+securityContext+"&value=other&math=2.3&list=[a,,b,]", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "other" || data.Attributes["math"] != "2.3" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 4 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
		}
	}

	t.Log("POST delete action on non list value, append on list value, add on number value")
	run("POST", path+"?"+securityContext+"&value=$DELETE&math=$ADD(1.7)&list=$APPEND(c,d)", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != nil || data.Attributes["math"].(string)[0:3] != "4.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 6 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "a" || valueList[1] != "" || valueList[2] != "b" || valueList[3] != "" || valueList[4] != "c" || valueList[5] != "d" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST new value to non list value, append on list value, add on number value")
	run("POST", path+"?"+securityContext+"&value=new&math=$INCR&list=$PREPEND(-2,-1,0,)", "204", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "new" || data.Attributes["math"].(string)[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 10 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of append on non list item")
	run("POST", path+"?"+securityContext+"&value=$APPEND(wrong)&math=$ADD(3.4)&list=$PREPEND(-2,-1,0,)", "409", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "new" || data.Attributes["math"].(string)[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 10 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of prepend on non list item")
	run("POST", path+"?"+securityContext+"&value=$PREPEND(wrong)&math=$INCR&list=$PREPEND(-2,-1,0,)", "409", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "new" || data.Attributes["math"].(string)[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 10 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of INCR on non num item")
	run("POST", path+"?"+securityContext+"&value=$INCR&math=$INCR&list=$PREPEND(-4,-3,)", "409", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "new" || data.Attributes["math"].(string)[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 10 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	t.Log("POST rollback because of ADD on non num item")
	run("POST", path+"?"+securityContext+"&value=$ADD(1.2)&math=$ADD(2.3)&list=$APPEND(e,f,)", "409", t)
	resp = run("GET", path+"?"+securityContext, "200", t)
	defer resp.Body.Close()
	if all, err := ioutil.ReadAll(resp.Body); err != nil {
		t.Log(err)
	} else {
		data := &Entity{}
		err := json.Unmarshal(all, data)
		if err != nil {
			t.Log(err)
		}
		if data.Type != "asdf" || data.Domain != "asdf" || data.Key != "asdf" || data.Attributes["value"] != "new" || data.Attributes["math"].(string)[0:3] != "5.0" {
			t.Errorf("State of database is different than expected, got: `" + string(all) + "`")
		}
		if valueList, ok := data.Attributes["list"].([]interface{}); !ok {
			t.Errorf("Expected entity attributes value key to contain array, got: `%T`", data.Attributes["value"])
		} else {
			if len(valueList) != 10 {
				t.Errorf("Expected entity attributes value key to have list of three items, had: `%d`", len(valueList))
			}
			if valueList[0] != "-2" || valueList[1] != "-1" || valueList[2] != "0" || valueList[3] != "" || valueList[4] != "a" || valueList[5] != "" {
				t.Errorf("Expected list to have certain values, instead got: : `%+v`", valueList)
			}
		}
	}

	// DELETE tests

	t.Log("DELETE")
	run("DELETE", path+"?"+securityContext, "204", t)
	run("GET", path+"?"+securityContext, "404", t)

	Cleanup()
}

type Entity struct {
	Type       string
	Domain     string
	Key        string
	LastUpdate string
	Attributes map[string]interface{}
}

type Attribute struct {
	Name  string
	Value interface{}
}
