// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewResponseRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	if !(recordRequest.ResponseWriter == w) {
		t.Fatalf("Expected Response writer in the Recording to be same as the one sent\n")
	}
	if recordRequest.status != http.StatusOK {
		t.Fatalf("Expected recorded status  to be http.StatusOK (%d) , but found %d\n ", http.StatusOK, recordRequest.status)
	}
}
func TestWriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	recordRequest := NewResponseRecorder(w)
	recordRequest.WriteHeader(401)
	if w.Code != 401 || recordRequest.status != 401 {
		t.Fatalf("Expected Response status to be set to 401, but found %d\n", recordRequest.status)
	}
}

func TestWrite(t *testing.T) {
	w := httptest.NewRecorder()
	responseTestString := "test"
	recordRequest := NewResponseRecorder(w)
	buf := []byte(responseTestString)
	_, _ = recordRequest.Write(buf)
	if recordRequest.size != len(buf) {
		t.Fatalf("Expected the bytes written counter to be %d, but instead found %d\n", len(buf), recordRequest.size)
	}
	if w.Body.String() != responseTestString {
		t.Fatalf("Expected Response Body to be %s , but found %s\n", responseTestString, w.Body.String())
	}
}
