package h2quic

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	dataStream   quic.Stream

	headerStream      quic.Stream
	headerStreamMutex *sync.Mutex

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool
}

func newResponseWriter(headerStream quic.Stream, headerStreamMutex *sync.Mutex, dataStream quic.Stream, dataStreamID protocol.StreamID) *responseWriter {
	return &responseWriter{
		header:            http.Header{},
		headerStream:      headerStream,
		headerStreamMutex: headerStreamMutex,
		dataStream:        dataStream,
		dataStreamID:      dataStreamID,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true
	w.status = status

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	utils.Infof("Responding with %d", status)
	w.headerStreamMutex.Lock()
	defer w.headerStreamMutex.Unlock()
	h2framer := http2.NewFramer(w.headerStream, nil)
	err := h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
	if err != nil {
		utils.Errorf("could not write h2 header: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	return w.dataStream.Write(p)
}

func (w *responseWriter) Flush() {}

// This is a NOP. Use http.Request.Context
func (w *responseWriter) CloseNotify() <-chan bool { return make(<-chan bool) }

// test that we implement http.Flusher
var _ http.Flusher = &responseWriter{}

// test that we implement http.CloseNotifier
var _ http.CloseNotifier = &responseWriter{}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
