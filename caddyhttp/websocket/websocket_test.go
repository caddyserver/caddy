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

package websocket

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBuildEnv(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatal("Error setting up request:", err)
	}
	req.RemoteAddr = "localhost:50302"

	env, err := buildEnv("/bin/command", req)
	if err != nil {
		t.Fatal("Didn't expect an error:", err)
	}
	if len(env) == 0 {
		t.Fatalf("Expected non-empty environment; got %#v", env)
	}
}

func TestWebSocketCatOneLineLines(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "lines"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputStr := "123456"
	expectedStr := inputStr
	outputStr := ""
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.TextMessage, []byte(inputStr), nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputStr += string(buf)
			waitClose <- true
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if outputStr != expectedStr {
		t.Errorf("Received Websocket response %v != %v", outputStr, expectedStr)
	}
}

func TestWebSocketCatTwoLinesLines(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "lines"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputStr1 := "Hello World!"
	inputStr2 := "This is golang."
	expectedStr := inputStr1 + inputStr2
	outputStr := ""
	outputCount := 0
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.TextMessage, []byte(inputStr1), nil
			}
			if rc == 1 {
				return websocket.TextMessage, []byte(inputStr2), nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputStr += string(buf)
			outputCount++
			if outputCount >= 2 {
				waitClose <- true
			}
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if outputStr != expectedStr {
		t.Errorf("Received Websocket response %v != %v", outputStr, expectedStr)
	}
}

func TestWebSocketCatOneLineText(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "text"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputStr := "123456\n"
	expectedStr := inputStr
	outputStr := ""
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.TextMessage, []byte(inputStr), nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputStr += string(buf)
			if strings.Count(outputStr, "\n") >= 1 {
				waitClose <- true
			}
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if outputStr != expectedStr {
		t.Errorf("Received Websocket response %v != %v", outputStr, expectedStr)
	}
}

func TestWebSocketCatTwoLinesText(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "text"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputStr1 := "Hello World!\n"
	inputStr2 := "This is golang.\n"
	expectedStr := inputStr1 + inputStr2
	outputStr := ""
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.TextMessage, []byte(inputStr1), nil
			}
			if rc == 1 {
				return websocket.TextMessage, []byte(inputStr2), nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputStr += string(buf)
			if strings.Count(outputStr, "\n") >= 2 {
				waitClose <- true
			}
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if outputStr != expectedStr {
		t.Errorf("Received Websocket response %v != %v", outputStr, expectedStr)
	}
}

func TestWebSocketCatLongLinesText(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "text"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputStr1 := "Hello World!\n"
	inputStr2 := ""
	for i := 0; i < 100000; i++ {
		inputStr2 += fmt.Sprintf("No newline %v.", i)
	}
	inputStr2 += "\n"
	inputStr3 := "End of message.\n"
	expectedStr := inputStr1 + inputStr2 + inputStr3
	outputStr := ""
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.TextMessage, []byte(inputStr1), nil
			}
			if rc == 1 {
				return websocket.TextMessage, []byte(inputStr2), nil
			}
			if rc == 2 {
				return websocket.TextMessage, []byte(inputStr3), nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputStr += string(buf)
			if strings.Count(outputStr, "\n") >= 3 {
				waitClose <- true
			}
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if outputStr != expectedStr {
		t.Errorf("Received Websocket response %v != %v", outputStr, expectedStr)
	}
}

func TestWebSocketCatBinary(t *testing.T) {
	r := httptest.NewRequest("GET", "/cat", nil)
	p := &WebSocket{Sockets: []Config{{Path: "/cat", Command: "cat", Type: "binary"}}}
	readCount := 0
	waitClose := make(chan bool)
	inputArr1 := []byte("Hello World!")
	inputArr2 := []byte("End of message.")
	expectedArr := make([]byte, 0)
	expectedArr = append(expectedArr, inputArr1...)
	expectedArr = append(expectedArr, inputArr2...)
	outputArr := make([]byte, 0)
	conn := &dummyWsConn{
		close: func() {},
		readMessage: func() (messageType int, buf []byte, err error) {
			rc := readCount
			readCount++
			if rc == 0 {
				return websocket.BinaryMessage, inputArr1, nil
			}
			if rc == 1 {
				return websocket.BinaryMessage, inputArr2, nil
			}
			<-waitClose
			return websocket.CloseMessage, nil, errors.New("EOF")
		},
		writeControl: func(messageType int, buf []byte) {},
		writeMessage: func(messageType int, buf []byte) {
			outputArr = append(outputArr, buf...)
			if len(outputArr) >= len(expectedArr) {
				waitClose <- true
			}
		},
	}
	w := &myResponseRecorder{o: httptest.NewRecorder(), u: &dummyWsUpgrader{c: conn}}
	p.ServeHTTP(w, r)
	if !bytes.Equal(outputArr, expectedArr) {
		t.Errorf("Received Websocket response %v != %v", outputArr, expectedArr)
	}
}

type myResponseRecorder struct {
	o *httptest.ResponseRecorder
	u *dummyWsUpgrader
}

func (t *myResponseRecorder) Header() http.Header {
	return t.o.Header()
}
func (t *myResponseRecorder) Write(buf []byte) (int, error) {
	return t.o.Write(buf)
}
func (t *myResponseRecorder) WriteHeader(code int) {
	t.o.WriteHeader(code)
}
func (t *myResponseRecorder) Result() *http.Response {
	return t.o.Result()
}
func (t *myResponseRecorder) GetUpgrader() wsUpgrader {
	return t.u
}

type dummyWsUpgrader struct {
	c *dummyWsConn
}

func (t *dummyWsUpgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (wsConn, error) {
	return t.c, nil
}

type dummyWsConn struct {
	close        func()
	readMessage  func() (messageType int, buf []byte, err error)
	writeControl func(messageType int, buf []byte)
	writeMessage func(messageType int, buf []byte)
}

func (c *dummyWsConn) Close() error {
	c.close()
	return nil
}
func (c *dummyWsConn) ReadMessage() (messageType int, p []byte, err error) {
	return c.readMessage()
}
func (c *dummyWsConn) SetPongHandler(h func(appData string) error) {
}
func (c *dummyWsConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *dummyWsConn) SetReadLimit(limit int64) {
}
func (c *dummyWsConn) SetWriteDeadline(t time.Time) error {
	return nil
}
func (c *dummyWsConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	c.writeControl(messageType, data)
	return nil
}
func (c *dummyWsConn) WriteMessage(messageType int, data []byte) error {
	c.writeMessage(messageType, data)
	return nil
}
