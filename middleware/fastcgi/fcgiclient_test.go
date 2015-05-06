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
	"io/ioutil"
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
// sepicify remote fcgi responer ip:port to test with php
// test failed if the remote fcgi(script) failed md5 verification
// and output "FAILED" in response
const (
	script_file = "/tank/www/fcgic_test.php"
	//ip_port = "remote-php-serv:59000"
	ip_port = "127.0.0.1:59000"
)

var (
	t_ *testing.T = nil
)

type FastCGIServer struct{}

func (s FastCGIServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	req.ParseMultipartForm(100000000)

	stat := "PASSED"
	fmt.Fprintln(resp, "-")
	file_num := 0
	{
		length := 0
		for k0, v0 := range req.Form {
			h := md5.New()
			io.WriteString(h, v0[0])
			md5 := fmt.Sprintf("%x", h.Sum(nil))

			length += len(k0)
			length += len(v0[0])

			// echo error when key != md5(val)
			if md5 != k0 {
				fmt.Fprintln(resp, "server:err ", md5, k0)
				stat = "FAILED"
			}
		}
		if req.MultipartForm != nil {
			file_num = len(req.MultipartForm.File)
			for kn, fns := range req.MultipartForm.File {
				//fmt.Fprintln(resp, "server:filekey ", kn )
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
					//fmt.Fprintln(resp, "server:filemd5 ", md5 )

					if kn != md5 {
						fmt.Fprintln(resp, "server:err ", md5, kn)
						stat = "FAILED"
					}
					//fmt.Fprintln(resp, "server:filename ", f.Filename )
				}
			}
		}

		fmt.Fprintln(resp, "server:got data length", length)
	}
	fmt.Fprintln(resp, "-"+stat+"-POST(", len(req.Form), ")-FILE(", file_num, ")--")
}

func sendFcgi(reqType int, fcgi_params map[string]string, data []byte, posts map[string]string, files map[string]string) (content []byte) {
	fcgi, err := Dial("tcp", ip_port)
	if err != nil {
		log.Println("err:", err)
		return
	}

	length := 0

	var resp *http.Response
	switch reqType {
	case 0:
		if len(data) > 0 {
			length = len(data)
			rd := bytes.NewReader(data)
			resp, err = fcgi.Post(fcgi_params, "", rd, rd.Len())
		} else if len(posts) > 0 {
			values := url.Values{}
			for k, v := range posts {
				values.Set(k, v)
				length += len(k) + 2 + len(v)
			}
			resp, err = fcgi.PostForm(fcgi_params, values)
		} else {
			resp, err = fcgi.Get(fcgi_params)
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
		resp, err = fcgi.PostFile(fcgi_params, values, files)
	}

	if err != nil {
		log.Println("err:", err)
		return
	}

	defer resp.Body.Close()
	content, err = ioutil.ReadAll(resp.Body)

	log.Println("c: send data length ≈", length, string(content))
	fcgi.Close()
	time.Sleep(1 * time.Second)

	if bytes.Index(content, []byte("FAILED")) >= 0 {
		t_.Error("Server return failed message")
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
		fo.Write(buf)
		h.Write(buf)
	}
	m = fmt.Sprintf("%x", h.Sum(nil))
	return
}

func Disabled_Test(t *testing.T) {
	// TODO: test chunked reader

	t_ = t
	rand.Seed(time.Now().UTC().UnixNano())

	// server
	go func() {
		listener, err := net.Listen("tcp", ip_port)
		if err != nil {
			// handle error
			log.Println("listener creatation failed: ", err)
		}

		srv := new(FastCGIServer)
		fcgi.Serve(listener, srv)
	}()

	time.Sleep(1 * time.Second)

	// init
	fcgi_params := make(map[string]string)
	fcgi_params["REQUEST_METHOD"] = "GET"
	fcgi_params["SERVER_PROTOCOL"] = "HTTP/1.1"
	//fcgi_params["GATEWAY_INTERFACE"] = "CGI/1.1"
	fcgi_params["SCRIPT_FILENAME"] = script_file

	// simple GET
	log.Println("test:", "get")
	sendFcgi(0, fcgi_params, nil, nil, nil)

	// simple post data
	log.Println("test:", "post")
	sendFcgi(0, fcgi_params, []byte("c4ca4238a0b923820dcc509a6f75849b=1&7b8b965ad4bca0e41ab51de7b31363a1=n"), nil, nil)

	log.Println("test:", "post data (more than 60KB)")
	data := ""
	length := 0
	for i := 0x00; i < 0xff; i++ {
		v0 := strings.Repeat(string(i), 256)
		h := md5.New()
		io.WriteString(h, v0)
		k0 := fmt.Sprintf("%x", h.Sum(nil))

		length += len(k0)
		length += len(v0)

		data += k0 + "=" + url.QueryEscape(v0) + "&"
	}
	sendFcgi(0, fcgi_params, []byte(data), nil, nil)

	log.Println("test:", "post form (use url.Values)")
	p0 := make(map[string]string, 1)
	p0["c4ca4238a0b923820dcc509a6f75849b"] = "1"
	p0["7b8b965ad4bca0e41ab51de7b31363a1"] = "n"
	sendFcgi(1, fcgi_params, nil, p0, nil)

	log.Println("test:", "post forms (256 keys, more than 1MB)")
	p1 := make(map[string]string, 1)
	for i := 0x00; i < 0xff; i++ {
		v0 := strings.Repeat(string(i), 4096)
		h := md5.New()
		io.WriteString(h, v0)
		k0 := fmt.Sprintf("%x", h.Sum(nil))
		p1[k0] = v0
	}
	sendFcgi(1, fcgi_params, nil, p1, nil)

	log.Println("test:", "post file (1 file, 500KB)) ")
	f0 := make(map[string]string, 1)
	path0, m0 := generateRandFile(500000)
	f0[m0] = path0
	sendFcgi(1, fcgi_params, nil, p1, f0)

	log.Println("test:", "post multiple files (2 files, 5M each) and forms (256 keys, more than 1MB data")
	path1, m1 := generateRandFile(5000000)
	f0[m1] = path1
	sendFcgi(1, fcgi_params, nil, p1, f0)

	log.Println("test:", "post only files (2 files, 5M each)")
	sendFcgi(1, fcgi_params, nil, nil, f0)

	log.Println("test:", "post only 1 file")
	delete(f0, "m0")
	sendFcgi(1, fcgi_params, nil, nil, f0)

	os.Remove(path0)
	os.Remove(path1)
}
