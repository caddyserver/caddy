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
