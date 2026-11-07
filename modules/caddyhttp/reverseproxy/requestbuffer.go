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

package reverseproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sync"

	"github.com/dustin/go-humanize"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// RequestBufferOptions extends request_buffers with opt-in disk buffering for
// unknown-length request bodies. These bodies are read to completion before
// dialing an upstream. Known-length bodies keep their memory-only buffering
// behavior. Read timeouts should bound how long uploads can hold buffers.
// With these options, exceeding a limit does not fall back to streaming.
type RequestBufferOptions struct {
	// The maximum total size of a request body. Larger bodies produce HTTP 413.
	// Default: 100 MiB. This does not limit requests of known length; use
	// request_body max_size for a limit that applies to all requests.
	MaxSize int64 `json:"max_size,omitempty"`

	// The aggregate temporary-file budget for concurrent requests handled by
	// this reverse_proxy handler. Each handler and config reload has its own
	// budget. Budget exhaustion produces HTTP 503. Default: 100 MiB.
	MaxDisk int64 `json:"max_disk,omitempty"`

	// Directory for temporary files. Defaults to the operating system's temp
	// directory. Files are created only when a body exceeds the memory threshold
	// and removed after proxying finishes, including retries. The directory must
	// already exist. Abrupt process termination can leave files behind.
	TempDir string `json:"temp_dir,omitempty"`

	memory    int64 // the request_buffers threshold, fixed at provision time
	mu        sync.Mutex
	diskUsage int64
}

func (b *RequestBufferOptions) provision(memory int64) error {
	if memory <= 0 {
		return fmt.Errorf("disk buffering requires a positive, finite request_buffers value")
	}
	if b.MaxSize < 0 || b.MaxDisk < 0 {
		return fmt.Errorf("buffer sizes must be positive")
	}
	b.memory = memory
	if b.MaxSize == 0 {
		b.MaxSize = 100 << 20
	}
	if b.MaxDisk == 0 {
		b.MaxDisk = 100 << 20
	}
	return nil
}

// parseRequestBufferOptions returns nil when there is no optional block.
func parseRequestBufferOptions(d *caddyfile.Dispenser) (*RequestBufferOptions, error) {
	var options *RequestBufferOptions
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if options == nil {
			options = new(RequestBufferOptions)
		}
		option := d.Val()
		args := d.RemainingArgs()
		if len(args) != 1 {
			return nil, d.ArgErr()
		}
		if option == "temp_dir" {
			options.TempDir = args[0]
			continue
		}
		size, err := humanize.ParseBytes(args[0])
		if err != nil || size == 0 || size > math.MaxInt64 {
			return nil, d.Errf("invalid positive byte size %q", args[0])
		}
		switch option {
		case "max_size":
			options.MaxSize = int64(size)
		case "max_disk":
			options.MaxDisk = int64(size)
		default:
			return nil, d.Errf("unrecognized request_buffers option %q", option)
		}
	}
	// NextBlock consumes both braces of an empty block without yielding an
	// option. The explicit block still opts into disk buffering with defaults.
	if options == nil && d.Val() == "}" {
		options = new(RequestBufferOptions)
	}
	return options, nil
}

func (b *RequestBufferOptions) reserve(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.MaxDisk-b.diskUsage {
		return false
	}
	b.diskUsage += n
	return true
}

func (b *RequestBufferOptions) release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.diskUsage -= n
}

// spooledBody owns its storage. Readers passed to transports are independent
// and cannot close it; ServeHTTP closes the owner once every attempt is done.
type spooledBody struct {
	memory    bytes.Buffer
	file      *os.File
	size      int64
	diskBytes int64
	budget    *RequestBufferOptions
	io.Reader
	closeOnce sync.Once
	closeErr  error
}

func (b *spooledBody) reader() io.Reader {
	if b.file != nil {
		return io.NewSectionReader(b.file, 0, b.size)
	}
	return bytes.NewReader(b.memory.Bytes())
}

func (b *spooledBody) Close() error {
	b.closeOnce.Do(func() {
		if b.file == nil {
			return
		}
		closeErr := b.file.Close()
		removeErr := os.Remove(b.file.Name()) //nolint:gosec // name comes from os.CreateTemp, not request data
		// Keep leaked files charged to the budget if removal fails.
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			b.budget.release(b.diskBytes)
			removeErr = nil
		}
		b.closeErr = errors.Join(closeErr, removeErr)
	})
	return b.closeErr
}

func (b *spooledBody) writeFile(p []byte) error {
	if !b.budget.reserve(int64(len(p))) {
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("request buffer disk budget exhausted"))
	}
	n, err := b.file.Write(p)
	b.diskBytes += int64(n)
	b.budget.release(int64(len(p) - n))
	if err != nil {
		return fmt.Errorf("writing request buffer: %w", err)
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *RequestBufferOptions) buffer(ctx context.Context, original io.ReadCloser) (_ *spooledBody, err error) {
	defer func() { _ = original.Close() }()
	body := &spooledBody{budget: c}
	defer func() {
		if err != nil {
			err = errors.Join(err, body.Close())
		}
	}()

	buf := streamingBufPool.Get().(*[]byte)
	defer streamingBufPool.Put(buf)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Read at most one byte beyond the limit, without overflowing int64.
		readSize := len(*buf)
		if remaining := c.MaxSize - body.size; remaining < int64(readSize) {
			readSize = int(remaining) + 1
		}
		n, readErr := original.Read((*buf)[:readSize])
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int64(n) > c.MaxSize-body.size {
			return nil, caddyhttp.Error(http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds request_buffers max_size"))
		}
		if n > 0 {
			if body.file == nil && int64(n) > c.memory-body.size {
				body.file, err = os.CreateTemp(c.TempDir, "caddy-request-buffer-*")
				if err != nil {
					return nil, fmt.Errorf("creating request buffer: %w", err)
				}
				if err := body.writeFile(body.memory.Bytes()); err != nil {
					return nil, err
				}
				body.memory = bytes.Buffer{}
			}
			if body.file != nil {
				if err := body.writeFile((*buf)[:n]); err != nil {
					return nil, err
				}
			} else {
				_, _ = body.memory.Write((*buf)[:n])
			}
			body.size += int64(n)
		}
		if readErr != nil {
			if readErr != io.EOF {
				status := http.StatusBadRequest
				if _, ok := errors.AsType[*http.MaxBytesError](readErr); ok {
					status = http.StatusRequestEntityTooLarge
				}
				return nil, caddyhttp.Error(status, fmt.Errorf("reading request body: %w", readErr))
			}
			body.Reader = body.reader()
			return body, nil
		}
	}
}
