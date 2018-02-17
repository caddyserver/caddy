package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type windowUpdateQueue struct {
	mutex sync.Mutex

	queue        map[protocol.StreamID]bool // used as a set
	callback     func(wire.Frame)
	cryptoStream cryptoStreamI
	streamGetter streamGetter
}

func newWindowUpdateQueue(streamGetter streamGetter, cryptoStream cryptoStreamI, cb func(wire.Frame)) *windowUpdateQueue {
	return &windowUpdateQueue{
		queue:        make(map[protocol.StreamID]bool),
		streamGetter: streamGetter,
		cryptoStream: cryptoStream,
		callback:     cb,
	}
}

func (q *windowUpdateQueue) Add(id protocol.StreamID) {
	q.mutex.Lock()
	q.queue[id] = true
	q.mutex.Unlock()
}

func (q *windowUpdateQueue) QueueAll() {
	q.mutex.Lock()
	var offset protocol.ByteCount
	for id := range q.queue {
		if id == q.cryptoStream.StreamID() {
			offset = q.cryptoStream.getWindowUpdate()
		} else {
			str, err := q.streamGetter.GetOrOpenReceiveStream(id)
			if err != nil || str == nil { // the stream can be nil if it was completed before dequeing the window update
				continue
			}
			offset = str.getWindowUpdate()
		}
		if offset == 0 { // can happen if we received a final offset, right after queueing the window update
			continue
		}
		q.callback(&wire.MaxStreamDataFrame{
			StreamID:   id,
			ByteOffset: offset,
		})
		delete(q.queue, id)
	}
	q.mutex.Unlock()
}
