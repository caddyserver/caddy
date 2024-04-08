// Copyright 2015 Matthew Holt and The Caddy Authors
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

// NOTE: These tests were adapted from the original
// repository from which this package was forked.
// The tests are slow (~10s) and in dire need of rewriting.
// As such, the tests have been disabled to speed up
// automated builds until they can be properly written.

package fastcgi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// test fcgi protocol includes:
// Get, Post, Post in multipart/form-data, and Post with files
// each key should be the md5 of the value or the file uploaded
// specify remote fcgi responder ip:port to test with php
// test failed if the remote fcgi(script) failed md5 verification
// and output "FAILED" in response
const (
	scriptFile = "/tank/www/fcgic_test.php"
	// ipPort = "remote-php-serv:59000"
	ipPort = "127.0.0.1:59000"
)

var globalt *testing.T

type FastCGIServer struct{}

func (s FastCGIServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if err := req.ParseMultipartForm(100000000); err != nil {
		log.Printf("[ERROR] failed to parse: %v", err)
	}

	stat := "PASSED"
	fmt.Fprintln(resp, "-")
	fileNum := 0
	{
		length := 0
		for k0, v0 := range req.Form {
			h := md5.New()
			_, _ = io.WriteString(h, v0[0])
			_md5 := fmt.Sprintf("%x", h.Sum(nil))

			length += len(k0)
			length += len(v0[0])

			// echo error when key != _md5(val)
			if _md5 != k0 {
				fmt.Fprintln(resp, "server:err ", _md5, k0)
				stat = "FAILED"
			}
		}
		if req.MultipartForm != nil {
			fileNum = len(req.MultipartForm.File)
			for kn, fns := range req.MultipartForm.File {
				// fmt.Fprintln(resp, "server:filekey ", kn )
				length += len(kn)
				for _, f := range fns {
					fd, err := f.Open()
					if err != nil {
						log.Println("server:", err)
						return
					}
					h := md5.New()
					l0, err := io.Copy(h, fd)
					if err != nil {
						log.Println(err)
						return
					}
					length += int(l0)
					defer fd.Close()
					md5 := fmt.Sprintf("%x", h.Sum(nil))
					// fmt.Fprintln(resp, "server:filemd5 ", md5 )

					if kn != md5 {
						fmt.Fprintln(resp, "server:err ", md5, kn)
						stat = "FAILED"
					}
					// fmt.Fprintln(resp, "server:filename ", f.Filename )
				}
			}
		}

		fmt.Fprintln(resp, "server:got data length", length)
	}
	fmt.Fprintln(resp, "-"+stat+"-POST(", len(req.Form), ")-FILE(", fileNum, ")--")
}

func sendFcgi(reqType int, fcgiParams map[string]string, data []byte, posts map[string]string, files map[string]string) (content []byte) {
	conn, err := net.Dial("tcp", ipPort)
	if err != nil {
		log.Println("err:", err)
		return
	}

	fcgi := client{rwc: conn, reqID: 1}

	length := 0

	var resp *http.Response
	switch reqType {
	case 0:
		if len(data) > 0 {
			length = len(data)
			rd := bytes.NewReader(data)
			resp, err = fcgi.Post(fcgiParams, "", "", rd, int64(rd.Len()))
		} else if len(posts) > 0 {
			values := url.Values{}
			for k, v := range posts {
				values.Set(k, v)
				length += len(k) + 2 + len(v)
			}
			resp, err = fcgi.PostForm(fcgiParams, values)
		} else {
			rd := bytes.NewReader(data)
			resp, err = fcgi.Get(fcgiParams, rd, int64(rd.Len()))
		}

	default:
		values := url.Values{}
		for k, v := range posts {
			values.Set(k, v)
			length += len(k) + 2 + len(v)
		}

		for k, v := range files {
			fi, _ := os.Lstat(v)
			length += len(k) + int(fi.Size())
		}
		resp, err = fcgi.PostFile(fcgiParams, values, files)
	}

	if err != nil {
		log.Println("err:", err)
		return
	}

	defer resp.Body.Close()
	content, _ = io.ReadAll(resp.Body)

	log.Println("c: send data length ≈", length, string(content))
	conn.Close()
	time.Sleep(250 * time.Millisecond)

	if bytes.Contains(content, []byte("FAILED")) {
		globalt.Error("Server return failed message")
	}

	return
}

func generateRandFile(size int) (p string, m string) {
	p = filepath.Join(os.TempDir(), "fcgict"+strconv.Itoa(rand.Int()))

	// open output file
	fo, err := os.Create(p)
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	h := md5.New()
	for i := 0; i < size/16; i++ {
		buf := make([]byte, 16)
		binary.PutVarint(buf, rand.Int63())
		if _, err := fo.Write(buf); err != nil {
			log.Printf("[ERROR] failed to write buffer: %v\n", err)
		}
		if _, err := h.Write(buf); err != nil {
			log.Printf("[ERROR] failed to write buffer: %v\n", err)
		}
	}
	m = fmt.Sprintf("%x", h.Sum(nil))
	return
}

func DisabledTest(t *testing.T) {
	// TODO: test chunked reader
	globalt = t

	// server
	go func() {
		listener, err := net.Listen("tcp", ipPort)
		if err != nil {
			log.Println("listener creation failed: ", err)
		}

		srv := new(FastCGIServer)
		if err := fcgi.Serve(listener, srv); err != nil {
			log.Print("[ERROR] failed to start server: ", err)
		}
	}()

	time.Sleep(250 * time.Millisecond)

	// init
	fcgiParams := make(map[string]string)
	fcgiParams["REQUEST_METHOD"] = "GET"
	fcgiParams["SERVER_PROTOCOL"] = "HTTP/1.1"
	// fcgi_params["GATEWAY_INTERFACE"] = "CGI/1.1"
	fcgiParams["SCRIPT_FILENAME"] = scriptFile

	// simple GET
	log.Println("test:", "get")
	sendFcgi(0, fcgiParams, nil, nil, nil)

	// simple post data
	log.Println("test:", "post")
	sendFcgi(0, fcgiParams, []byte("c4ca4238a0b923820dcc509a6f75849b=1&7b8b965ad4bca0e41ab51de7b31363a1=n"), nil, nil)

	log.Println("test:", "post data (more than 60KB)")
	data := ""
	for i := 0x00; i < 0xff; i++ {
		v0 := strings.Repeat(fmt.Sprint(i), 256)
		h := md5.New()
		_, _ = io.WriteString(h, v0)
		k0 := fmt.Sprintf("%x", h.Sum(nil))
		data += k0 + "=" + url.QueryEscape(v0) + "&"
	}
	sendFcgi(0, fcgiParams, []byte(data), nil, nil)

	log.Println("test:", "post form (use url.Values)")
	p0 := make(map[string]string, 1)
	p0["c4ca4238a0b923820dcc509a6f75849b"] = "1"
	p0["7b8b965ad4bca0e41ab51de7b31363a1"] = "n"
	sendFcgi(1, fcgiParams, nil, p0, nil)

	log.Println("test:", "post forms (256 keys, more than 1MB)")
	p1 := make(map[string]string, 1)
	for i := 0x00; i < 0xff; i++ {
		v0 := strings.Repeat(fmt.Sprint(i), 4096)
		h := md5.New()
		_, _ = io.WriteString(h, v0)
		k0 := fmt.Sprintf("%x", h.Sum(nil))
		p1[k0] = v0
	}
	sendFcgi(1, fcgiParams, nil, p1, nil)

	log.Println("test:", "post file (1 file, 500KB)) ")
	f0 := make(map[string]string, 1)
	path0, m0 := generateRandFile(500000)
	f0[m0] = path0
	sendFcgi(1, fcgiParams, nil, p1, f0)

	log.Println("test:", "post multiple files (2 files, 5M each) and forms (256 keys, more than 1MB data")
	path1, m1 := generateRandFile(5000000)
	f0[m1] = path1
	sendFcgi(1, fcgiParams, nil, p1, f0)

	log.Println("test:", "post only files (2 files, 5M each)")
	sendFcgi(1, fcgiParams, nil, nil, f0)

	log.Println("test:", "post only 1 file")
	delete(f0, "m0")
	sendFcgi(1, fcgiParams, nil, nil, f0)

	if err := os.Remove(path0); err != nil {
		log.Println("[ERROR] failed to remove path: ", err)
	}
	if err := os.Remove(path1); err != nil {
		log.Println("[ERROR] failed to remove path: ", err)
	}
}
