package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type streamsMapLegacy struct {
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

	numOutgoingStreams uint32
	numIncomingStreams uint32
	maxIncomingStreams uint32
	maxOutgoingStreams uint32
}

var _ streamManager = &streamsMapLegacy{}

func newStreamsMapLegacy(newStream newStreamLambda, pers protocol.Perspective) streamManager {
	// add some tolerance to the maximum incoming streams value
	maxStreams := uint32(protocol.MaxIncomingStreams)
	maxIncomingStreams := utils.MaxUint32(
		maxStreams+protocol.MaxStreamsMinimumIncrement,
		uint32(float64(maxStreams)*float64(protocol.MaxStreamsMultiplier)),
	)
	sm := streamsMapLegacy{
		perspective:        pers,
		streams:            make(map[protocol.StreamID]streamI),
		newStream:          newStream,
		maxIncomingStreams: maxIncomingStreams,
	}
	sm.nextStreamOrErrCond.L = &sm.mutex
	sm.openStreamOrErrCond.L = &sm.mutex

	nextServerInitiatedStream := protocol.StreamID(2)
	nextClientInitiatedStream := protocol.StreamID(3)
	if pers == protocol.PerspectiveServer {
		sm.highestStreamOpenedByPeer = 1
	}
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
func (m *streamsMapLegacy) streamInitiatedBy(id protocol.StreamID) protocol.Perspective {
	if id%2 == 0 {
		return protocol.PerspectiveServer
	}
	return protocol.PerspectiveClient
}

func (m *streamsMapLegacy) GetOrOpenReceiveStream(id protocol.StreamID) (receiveStreamI, error) {
	// every bidirectional stream is also a receive stream
	return m.GetOrOpenStream(id)
}

func (m *streamsMapLegacy) GetOrOpenSendStream(id protocol.StreamID) (sendStreamI, error) {
	// every bidirectional stream is also a send stream
	return m.GetOrOpenStream(id)
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (m *streamsMapLegacy) GetOrOpenStream(id protocol.StreamID) (streamI, error) {
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

	for sid := m.highestStreamOpenedByPeer + 2; sid <= id; sid += 2 {
		if _, err := m.openRemoteStream(sid); err != nil {
			return nil, err
		}
	}

	m.nextStreamOrErrCond.Broadcast()
	return m.streams[id], nil
}

func (m *streamsMapLegacy) openRemoteStream(id protocol.StreamID) (streamI, error) {
	if m.numIncomingStreams >= m.maxIncomingStreams {
		return nil, qerr.TooManyOpenStreams
	}
	if id+protocol.MaxNewStreamIDDelta < m.highestStreamOpenedByPeer {
		return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("attempted to open stream %d, which is a lot smaller than the highest opened stream, %d", id, m.highestStreamOpenedByPeer))
	}

	m.numIncomingStreams++
	if id > m.highestStreamOpenedByPeer {
		m.highestStreamOpenedByPeer = id
	}

	s := m.newStream(id)
	return s, m.putStream(s)
}

func (m *streamsMapLegacy) openStreamImpl() (streamI, error) {
	if m.numOutgoingStreams >= m.maxOutgoingStreams {
		return nil, qerr.TooManyOpenStreams
	}

	m.numOutgoingStreams++
	s := m.newStream(m.nextStreamToOpen)
	m.nextStreamToOpen += 2
	return s, m.putStream(s)
}

// OpenStream opens the next available stream
func (m *streamsMapLegacy) OpenStream() (Stream, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}
	return m.openStreamImpl()
}

func (m *streamsMapLegacy) OpenStreamSync() (Stream, error) {
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
func (m *streamsMapLegacy) AcceptStream() (Stream, error) {
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

func (m *streamsMapLegacy) DeleteStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, ok := m.streams[id]
	if !ok {
		return errMapAccess
	}
	delete(m.streams, id)
	if m.streamInitiatedBy(id) == m.perspective {
		m.numOutgoingStreams--
	} else {
		m.numIncomingStreams--
	}
	m.openStreamOrErrCond.Signal()
	return nil
}

func (m *streamsMapLegacy) putStream(s streamI) error {
	id := s.StreamID()
	if _, ok := m.streams[id]; ok {
		return fmt.Errorf("a stream with ID %d already exists", id)
	}
	m.streams[id] = s
	return nil
}

func (m *streamsMapLegacy) CloseWithError(err error) {
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
func (m *streamsMapLegacy) UpdateLimits(params *handshake.TransportParameters) {
	m.mutex.Lock()
	m.maxOutgoingStreams = params.MaxStreams
	for id, str := range m.streams {
		str.handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
			StreamID:   id,
			ByteOffset: params.StreamFlowControlWindow,
		})
	}
	m.mutex.Unlock()
	m.openStreamOrErrCond.Broadcast()
}
