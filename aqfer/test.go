package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
)

func main() {
	http.HandleFunc("/", Auth)
	http.ListenAndServe(":8081", nil)
}

func init() {
}

type Claims struct {
	jwt.StandardClaims
	User  string   `json:"user"`
	Email string   `json:"email"`
	Scope []string `json:"scope"`
	Type  string   `json:"type"`
	Roles []string `json:"role"`
}

func Auth(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	refreshToken := r.Form["refresh_token"]
	fmt.Println(refreshToken)

	accessToken, _ := GenerateAccessToken()

	if strings.Contains(r.URL.Path, "security_context") {
		w.Write([]byte("{\"scope\":{\"cids\":[\"c009\"]}}"))
	} else {
		w.Write([]byte("{\"expires_in\": 7200,\"jwt_token\": \"" + accessToken + "\",\"purpose\": \"access_token\",\"type\": \"Bearer\"}"))
	}
	w.WriteHeader(200)
	return
}

func GenerateAccessToken() (string, error) {
	now := time.Now().Unix()
	uuid, _ := uuid.NewV1()
	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.String(),
			IssuedAt:  now,
			ExpiresAt: now + 7200,
		},
		User:  "test",
		Email: "test@user.com",
		Scope: []string{"asdf"},
		Type:  "access_token",
		Roles: []string{},
	}
	tkn, err := mkJwtToken("testkey", claims)
	if err == nil {
		return tkn, nil
	}
	return "", err
}

func mkJwtToken(key string, claims Claims) (string, error) {
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tkn.SignedString([]byte(key))
}
