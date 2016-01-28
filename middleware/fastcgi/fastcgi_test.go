package fastcgi

import (
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
