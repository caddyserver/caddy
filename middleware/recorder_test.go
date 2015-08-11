package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNewResponseRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	if !reflect.DeepEqual(recordRequest.ResponseWriter, w) {
		t.Fatalf("Expected Response writer in the Recording to be same as the one sent")
	}
	if recordRequest.status != http.StatusOK {
		t.Fatalf("Expected recorded status  to be http.StatusOK")
	}
}
