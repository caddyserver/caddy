package proxy

import (
	"bytes"
	"io"
	"io/ioutil"
)

type bufferedBody struct {
	*bytes.Reader
}

func (*bufferedBody) Close() error {
	return nil
}

// rewind allows bufferedBody to be read again.
func (b *bufferedBody) rewind() error {
	if b == nil {
		return nil
	}
	_, err := b.Seek(0, io.SeekStart)
	return err
}

// newBufferedBody returns *bufferedBody to use in place of src. Closes src
// and returns Read error on src. All content from src is buffered.
func newBufferedBody(src io.ReadCloser) (*bufferedBody, error) {
	if src == nil {
		return nil, nil
	}
	b, err := ioutil.ReadAll(src)
	src.Close()
	if err != nil {
		return nil, err
	}
	return &bufferedBody{
		Reader: bytes.NewReader(b),
	}, nil
}
