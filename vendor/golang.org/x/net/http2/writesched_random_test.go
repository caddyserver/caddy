// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import "testing"

func TestRandomScheduler(t *testing.T) {
	ws := NewRandomWriteScheduler()
	ws.Push(makeWriteHeadersRequest(3))
	ws.Push(makeWriteHeadersRequest(4))
	ws.Push(makeWriteHeadersRequest(1))
	ws.Push(makeWriteHeadersRequest(2))
	ws.Push(makeWriteNonStreamRequest())
	ws.Push(makeWriteNonStreamRequest())

	// Pop all frames. Should get the non-stream requests first,
	// followed by the stream requests in any order.
	var order []FrameWriteRequest
	for {
		wr, ok := ws.Pop()
		if !ok {
			break
		}
		order = append(order, wr)
	}
	t.Logf("got frames: %v", order)
	if len(order) != 6 {
		t.Fatalf("got %d frames, expected 6", len(order))
	}
	if order[0].StreamID() != 0 || order[1].StreamID() != 0 {
		t.Fatal("expected non-stream frames first", order[0], order[1])
	}
	got := make(map[uint32]bool)
	for _, wr := range order[2:] {
		got[wr.StreamID()] = true
	}
	for id := uint32(1); id <= 4; id++ {
		if !got[id] {
			t.Errorf("frame not found for stream %d", id)
		}
	}
}
