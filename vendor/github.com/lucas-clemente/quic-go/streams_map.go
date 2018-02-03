package quic

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type streamsMap struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	streams map[protocol.StreamID]streamI

	nextStreamToOpen          protocol.StreamID // StreamID of the next Stream that will be returned by OpenStream()
	highestStreamOpenedByPeer protocol.StreamID
	nextStreamOrErrCond       sync.Cond
	openStreamOrErrCond       sync.Cond

	closeErr           error
	nextStreamToAccept protocol.StreamID

	newStream newStreamLambda
}

var _ streamManager = &streamsMap{}

type newStreamLambda func(protocol.StreamID) streamI

var errMapAccess = errors.New("streamsMap: Error accessing the streams map")

func newStreamsMap(newStream newStreamLambda, pers protocol.Perspective) streamManager {
	sm := streamsMap{
		perspective: pers,
		streams:     make(map[protocol.StreamID]streamI),
		newStream:   newStream,
	}
	sm.nextStreamOrErrCond.L = &sm.mutex
	sm.openStreamOrErrCond.L = &sm.mutex

	nextClientInitiatedStream := protocol.StreamID(1)
	nextServerInitiatedStream := protocol.StreamID(2)
	if pers == protocol.PerspectiveServer {
		sm.nextStreamToOpen = nextServerInitiatedStream
		sm.nextStreamToAccept = nextClientInitiatedStream
	} else {
		sm.nextStreamToOpen = nextClientInitiatedStream
		sm.nextStreamToAccept = nextServerInitiatedStream
	}
	return &sm
}

// getStreamPerspective says which side should initiate a stream
func (m *streamsMap) streamInitiatedBy(id protocol.StreamID) protocol.Perspective {
	if id%2 == 0 {
		return protocol.PerspectiveServer
	}
	return protocol.PerspectiveClient
}

func (m *streamsMap) nextStreamID(id protocol.StreamID) protocol.StreamID {
	if m.perspective == protocol.PerspectiveServer && id == 0 {
		return 1
	}
	return id + 2
}

func (m *streamsMap) GetOrOpenReceiveStream(id protocol.StreamID) (receiveStreamI, error) {
	// every bidirectional stream is also a receive stream
	return m.GetOrOpenStream(id)
}

func (m *streamsMap) GetOrOpenSendStream(id protocol.StreamID) (sendStreamI, error) {
	// every bidirectional stream is also a send stream
	return m.GetOrOpenStream(id)
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (m *streamsMap) GetOrOpenStream(id protocol.StreamID) (streamI, error) {
	m.mutex.RLock()
	s, ok := m.streams[id]
	m.mutex.RUnlock()
	if ok {
		return s, nil
	}

	// ... we don't have an existing stream
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// We need to check whether another invocation has already created a stream (between RUnlock() and Lock()).
	s, ok = m.streams[id]
	if ok {
		return s, nil
	}

	if m.perspective == m.streamInitiatedBy(id) {
		if id <= m.nextStreamToOpen { // this is a stream opened by us. Must have been closed already
			return nil, nil
		}
		return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("peer attempted to open stream %d", id))
	}
	if id <= m.highestStreamOpenedByPeer { // this is a peer-initiated stream that doesn't exist anymore. Must have been closed already
		return nil, nil
	}

	for sid := m.nextStreamID(m.highestStreamOpenedByPeer); sid <= id; sid = m.nextStreamID(sid) {
		if _, err := m.openRemoteStream(sid); err != nil {
			return nil, err
		}
	}

	m.nextStreamOrErrCond.Broadcast()
	return m.streams[id], nil
}

func (m *streamsMap) openRemoteStream(id protocol.StreamID) (streamI, error) {
	if id+protocol.MaxNewStreamIDDelta < m.highestStreamOpenedByPeer {
		return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("attempted to open stream %d, which is a lot smaller than the highest opened stream, %d", id, m.highestStreamOpenedByPeer))
	}
	if id > m.highestStreamOpenedByPeer {
		m.highestStreamOpenedByPeer = id
	}
	s := m.newStream(id)
	return s, m.putStream(s)
}

func (m *streamsMap) openStreamImpl() (streamI, error) {
	s := m.newStream(m.nextStreamToOpen)
	m.nextStreamToOpen = m.nextStreamID(m.nextStreamToOpen)
	return s, m.putStream(s)
}

// OpenStream opens the next available stream
func (m *streamsMap) OpenStream() (Stream, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}
	return m.openStreamImpl()
}

func (m *streamsMap) OpenStreamSync() (Stream, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for {
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, err := m.openStreamImpl()
		if err == nil {
			return str, err
		}
		if err != nil && err != qerr.TooManyOpenStreams {
			return nil, err
		}
		m.openStreamOrErrCond.Wait()
	}
}

// AcceptStream returns the next stream opened by the peer
// it blocks until a new stream is opened
func (m *streamsMap) AcceptStream() (Stream, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var str streamI
	for {
		var ok bool
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, ok = m.streams[m.nextStreamToAccept]
		if ok {
			break
		}
		m.nextStreamOrErrCond.Wait()
	}
	m.nextStreamToAccept += 2
	return str, nil
}

func (m *streamsMap) DeleteStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, ok := m.streams[id]
	if !ok {
		return errMapAccess
	}
	delete(m.streams, id)
	m.openStreamOrErrCond.Signal()
	return nil
}

func (m *streamsMap) putStream(s streamI) error {
	id := s.StreamID()
	if _, ok := m.streams[id]; ok {
		return fmt.Errorf("a stream with ID %d already exists", id)
	}
	m.streams[id] = s
	return nil
}

func (m *streamsMap) CloseWithError(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.closeErr = err
	m.nextStreamOrErrCond.Broadcast()
	m.openStreamOrErrCond.Broadcast()
	for _, s := range m.streams {
		s.closeForShutdown(err)
	}
}

// TODO(#952): this won't be needed when gQUIC supports stateless handshakes
func (m *streamsMap) UpdateLimits(params *handshake.TransportParameters) {
	m.mutex.Lock()
	for id, str := range m.streams {
		str.handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
			StreamID:   id,
			ByteOffset: params.StreamFlowControlWindow,
		})
	}
	m.mutex.Unlock()
	m.openStreamOrErrCond.Broadcast()
}
