package protocol

// A StreamID in QUIC
type StreamID uint64

// MaxBidiStreamID is the highest stream ID that the peer is allowed to open,
// when it is allowed to open numStreams bidirectional streams.
// It is only valid for IETF QUIC.
func MaxBidiStreamID(numStreams int, pers Perspective) StreamID {
	if numStreams == 0 {
		return 0
	}
	var first StreamID
	if pers == PerspectiveClient {
		first = 1
	} else {
		first = 4
	}
	return first + 4*StreamID(numStreams-1)
}

// MaxUniStreamID is the highest stream ID that the peer is allowed to open,
// when it is allowed to open numStreams unidirectional streams.
// It is only valid for IETF QUIC.
func MaxUniStreamID(numStreams int, pers Perspective) StreamID {
	if numStreams == 0 {
		return 0
	}
	var first StreamID
	if pers == PerspectiveClient {
		first = 3
	} else {
		first = 2
	}
	return first + 4*StreamID(numStreams-1)
}
