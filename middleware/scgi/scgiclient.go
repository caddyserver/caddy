package scgi

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
)

// Client implements a SCGI client, which is a standard for
// interfacing external applications with Web servers.
type Client struct {
	rwc    io.ReadWriteCloser
	stderr bytes.Buffer
}

// DialWithDialer connects to the scgi responder at the specified network address, using custom net.Dialer.
// See func net.Dial for a description of the network and address parameters.
func DialWithDialer(network, address string, dialer net.Dialer) (scgi *Client, err error) {
	var conn net.Conn
	conn, err = dialer.Dial(network, address)
	if err != nil {
		return
	}

	scgi = &Client{
		rwc: conn,
	}

	return
}

// Dial connects to the scgi responder at the specified network address, using default net.Dialer.
// See func net.Dial for a description of the network and address parameters.
func Dial(network, address string) (scgi *Client, err error) {
	return DialWithDialer(network, address, net.Dialer{})
}

// Close closes scgi connnection
func (c *Client) Close() {
	c.rwc.Close()
}

type netString struct {
	buf bytes.Buffer
}

func (n *netString) writePair(key string, val string) error {
	if err := n.write(key); err != nil {
		return err
	}
	return n.write(val)
}

func (n *netString) write(content string) error {
	if _, err := n.buf.WriteString(content); err != nil {
		return err
	}
	return n.buf.WriteByte(0)
}

func (n *netString) writeTo(w io.Writer) error {
	if _, err := w.Write([]byte(strconv.Itoa(n.buf.Len()) + ":")); err != nil {
		return err
	}
	if _, err := n.buf.WriteString(","); err != nil {
		return err
	}
	_, err := w.Write(n.buf.Bytes())
	return err
}

func (c *Client) writePairs(pairs map[string]string) error {
	ns := netString{}

	// CONTENT_LENGTH should be at first
	k := "CONTENT_LENGTH"
	v, ok := pairs[k]
	if !ok {
		return errors.New("scgi: CONTENT_LENGTH in not defined")
	}
	if err := ns.writePair(k, v); err != nil {
		return err
	}
	delete(pairs, k)

	for k, v := range pairs {
		if err := ns.writePair(k, v); err != nil {
			return err
		}
	}
	return ns.writeTo(c.rwc)
}

type streamReader struct {
	c *Client
}

func (w *streamReader) Read(p []byte) (int, error) {
	return w.c.rwc.Read(p)
}

// Do made the request and returns a io.Reader that translates the data read
// from scgi responder out of scgi packet before returning it.
func (c *Client) Do(p map[string]string, req io.Reader) (r io.Reader, err error) {
	err = c.writePairs(p)
	if err != nil {
		return
	}

	if req != nil {
		io.Copy(c.rwc, req)
	}

	r = &streamReader{c: c}
	return
}

// clientCloser is a io.ReadCloser. It wraps a io.Reader with a Closer
// that closes Client connection.
type clientCloser struct {
	*Client
	io.Reader
}

func (f clientCloser) Close() error { return f.rwc.Close() }

// Request returns a HTTP Response with Header and Body
// from scgi responder
func (c *Client) Request(p map[string]string, req io.Reader) (resp *http.Response, err error) {

	r, err := c.Do(p, req)
	if err != nil {
		return
	}

	rb := bufio.NewReader(r)
	tp := textproto.NewReader(rb)
	resp = new(http.Response)

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return
	}
	resp.Header = http.Header(mimeHeader)

	if resp.Header.Get("Status") != "" {
		statusParts := strings.SplitN(resp.Header.Get("Status"), " ", 2)
		resp.StatusCode, err = strconv.Atoi(statusParts[0])
		if err != nil {
			return
		}
		if len(statusParts) > 1 {
			resp.Status = statusParts[1]
		}

	} else {
		resp.StatusCode = http.StatusOK
	}

	// TODO: fixTransferEncoding ?
	resp.TransferEncoding = resp.Header["Transfer-Encoding"]
	resp.ContentLength, _ = strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	if chunked(resp.TransferEncoding) {
		resp.Body = clientCloser{c, httputil.NewChunkedReader(rb)}
	} else {
		resp.Body = clientCloser{c, ioutil.NopCloser(rb)}
	}
	return
}

// Get issues a GET request to the scgi responder.
func (c *Client) Get(p map[string]string) (resp *http.Response, err error) {

	p["REQUEST_METHOD"] = "GET"
	p["CONTENT_LENGTH"] = "0"

	return c.Request(p, nil)
}

// Head issues a HEAD request to the scgi responder.
func (c *Client) Head(p map[string]string) (resp *http.Response, err error) {

	p["REQUEST_METHOD"] = "HEAD"
	p["CONTENT_LENGTH"] = "0"

	return c.Request(p, nil)
}

// Options issues an OPTIONS request to the scgi responder.
func (c *Client) Options(p map[string]string) (resp *http.Response, err error) {

	p["REQUEST_METHOD"] = "OPTIONS"
	p["CONTENT_LENGTH"] = "0"

	return c.Request(p, nil)
}

// Post issues a POST request to the scgi responder. with request body
// in the format that bodyType specified
func (c *Client) Post(p map[string]string, method string, bodyType string, body io.Reader, l int) (resp *http.Response, err error) {
	if p == nil {
		p = make(map[string]string)
	}

	p["REQUEST_METHOD"] = strings.ToUpper(method)

	if len(p["REQUEST_METHOD"]) == 0 || p["REQUEST_METHOD"] == "GET" {
		p["REQUEST_METHOD"] = "POST"
	}

	p["CONTENT_LENGTH"] = strconv.Itoa(l)
	if len(bodyType) > 0 {
		p["CONTENT_TYPE"] = bodyType
	} else {
		p["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
	}

	return c.Request(p, body)
}

// Checks whether chunked is part of the encodings stack
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }
