package fastcgi

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRuleParseAddress(t *testing.T) {

	getClientTestTable := []struct {
		rule            *Rule
		expectednetwork string
		expectedaddress string
	}{
		{&Rule{Address: "tcp://172.17.0.1:9000"}, "tcp", "172.17.0.1:9000"},
		{&Rule{Address: "fastcgi://localhost:9000"}, "tcp", "localhost:9000"},
		{&Rule{Address: "172.17.0.15"}, "tcp", "172.17.0.15"},
		{&Rule{Address: "/my/unix/socket"}, "unix", "/my/unix/socket"},
		{&Rule{Address: "unix:/second/unix/socket"}, "unix", "/second/unix/socket"},
	}

	for _, entry := range getClientTestTable {
		if actualnetwork, _ := entry.rule.parseAddress(); actualnetwork != entry.expectednetwork {
			t.Errorf("Unexpected network for address string %v. Got %v, expected %v", entry.rule.Address, actualnetwork, entry.expectednetwork)
		}
		if _, actualaddress := entry.rule.parseAddress(); actualaddress != entry.expectedaddress {
			t.Errorf("Unexpected parsed address for address string %v. Got %v, expected %v", entry.rule.Address, actualaddress, entry.expectedaddress)
		}

	}

}

func TestBuildEnv(t *testing.T) {

	buildEnvSingle := func(r *http.Request, rule Rule, fpath string, envExpected map[string]string, t *testing.T) {

		h := Handler{}

		env, err := h.buildEnv(r, rule, fpath)
		if err != nil {
			t.Error("Unexpected error:", err.Error())
		}

		for k, v := range envExpected {
			if env[k] != v {
				t.Errorf("Unexpected %v. Got %v, expected %v", k, env[k], v)
			}
		}

	}

	rule := Rule{}
	url, err := url.Parse("http://localhost:2015/fgci_test.php?test=blabla")
	if err != nil {
		t.Error("Unexpected error:", err.Error())
	}

	r := http.Request{
		Method:     "GET",
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       "localhost:2015",
		RemoteAddr: "[2b02:1810:4f2d:9400:70ab:f822:be8a:9093]:51688",
		RequestURI: "/fgci_test.php",
	}

	fpath := "/fgci_test.php"

	var envExpected = map[string]string{
		"REMOTE_ADDR":     "[2b02:1810:4f2d:9400:70ab:f822:be8a:9093]",
		"REMOTE_PORT":     "51688",
		"SERVER_PROTOCOL": "HTTP/1.1",
		"QUERY_STRING":    "test=blabla",
		"REQUEST_METHOD":  "GET",
		"HTTP_HOST":       "localhost:2015",
	}

	// 1. Test for full canonical IPv6 address
	buildEnvSingle(&r, rule, fpath, envExpected, t)

	// 2. Test for shorthand notation of IPv6 address
	r.RemoteAddr = "[::1]:51688"
	envExpected["REMOTE_ADDR"] = "[::1]"
	buildEnvSingle(&r, rule, fpath, envExpected, t)

	// 3. Test for IPv4 address
	r.RemoteAddr = "192.168.0.10:51688"
	envExpected["REMOTE_ADDR"] = "192.168.0.10"
	buildEnvSingle(&r, rule, fpath, envExpected, t)

}
