package auth

import (
	"testing"
	"reflect"
	"log"
)

func TestService_GetVersion(t *testing.T) {
	s := Service{}
	vi, err := s.GetVersion()
	if !reflect.DeepEqual(vi.Version, version) {
		t.Errorf("expected %s, but got %s", version, vi.Version)
	}
	if err != nil {
		t.Errorf("unexpected error %s", err)
	}
}


func TestService_GenerateAccessToken(t *testing.T) {
	sc := SecurityContext{
		User: "testuser",
		Email: "testuser@testdomain.com",
		Scope: map[string]interface{} {"cids": "*"},
		Type: "refresh_token",
		Roles: []string{"access_key_validator"},
	}
	s := Service{SecurityContext: &sc, AccessKeySigningKey: "testkey"}
	ak, err := s.GenerateAccessToken()
	if err != nil {
		t.Errorf("unexpected error %s", err)
	} else {
		if ak.Type != "Bearer" {
			t.Errorf("expected type: %s, got %s", "Bearer", ak.Type)
		}
		log.Printf("%s", ak)

		newSc, err := s.ValidateToken(ak.AccessToken)
		if err != nil {
			t.Errorf("unexpected error %s", err)
		} else if newSc.User != "testuser" {
			t.Errorf("expected user in new security context: %s, got %s", "testuser", newSc.User)
		}
	}
}
