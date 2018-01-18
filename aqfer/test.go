package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", Auth)
	http.ListenAndServe(":8083", nil)
}

func Auth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
