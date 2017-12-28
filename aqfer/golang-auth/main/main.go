package main

import (
	auth ".."
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", Auth)
	http.ListenAndServe(":8083", nil)
}

func Auth(w http.ResponseWriter, r *http.Request) {
	authorizations := r.Header["Authorization"]
	token := authorizations[0][7:]
	// fmt.Printf("Received Refresh Token: %+v\n", token)

	sc := auth.SecurityContext{
		User:  "testuser",
		Email: "testuser@testdomain.com",
		Scope: map[string]interface{}{"cids": "*"},
		Type:  "refresh_token",
		Roles: []string{"access_key_validator"},
	}
	s := auth.Service{SecurityContext: &sc, AccessKeySigningKey: "testkey"}

	if _, err := s.ValidateToken(token); err != nil {
		fmt.Printf("error: %s", err.Error())
	} else {
		// tkn, _ := s.GenerateAccessToken()
		// fmt.Printf("New Access Token: %+v\n", tkn)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sc)
		return
	}
	w.WriteHeader(401)
}
