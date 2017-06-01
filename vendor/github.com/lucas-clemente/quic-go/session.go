package quic

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   net.Addr
	publicHeader *PublicHeader
	data         []byte
	rcvTime      time.Time
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
	errSessionAlreadyClosed       = errors.New("cannot close session; it was already closed before")
)

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

type handshakeEvent struct {
	encLevel protocol.EncryptionLevel
	err      error
}

type closeError struct {
	err    error
	remote bool
}

// A Session is a QUIC session
type session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	config       *Config

	conn connection

	streamsMap *streamsMap

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	streamFramer          *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	runClosed chan struct{}
	closed    uint32 // atomic bool

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the current encryption level
	// it is closed as soon as the handshake is complete
	aeadChanged       <-chan protocol.EncryptionLevel
	handshakeComplete bool
	// will be closed as soon as the handshake completes, and receive any error that might occur until then
	// it is used to block WaitUntilHandshakeComplete()
	handshakeCompleteChan chan error
	// handshakeChan receives handshake events and is closed as soon the handshake completes
	// the receiving end of this channel is passed to the creator of the session
	// it receives at most 3 handshake events: 2 when the encryption level changes, and one error
	handshakeChan chan<- handshakeEvent

	nextAckScheduledTime time.Time

	connectionParameters handshake.ConnectionParametersManager

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time

	timer           *time.Timer
	currentDeadline time.Time
	timerRead       bool
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	config *Config,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,

		connectionParameters: handshake.NewConnectionParamatersManager(protocol.PerspectiveServer, v),
	}

	s.setup()
	cryptoStream, _ := s.GetOrOpenStream(1)
	_, _ = s.AcceptStream() // don't expose the crypto stream
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	verifySourceAddr := func(clientAddr net.Addr, hstk *handshake.STK) bool {
		if hstk == nil {
			return config.AcceptSTK(clientAddr, nil)
		}
		return config.AcceptSTK(
			clientAddr,
			&STK{remoteAddr: hstk.RemoteAddr, sentTime: hstk.SentTime},
		)
	}
	var err error
	s.cryptoSetup, err = newCryptoSetup(
		connectionID,
		conn.RemoteAddr(),
		v,
		sCfg,
		cryptoStream,
		s.connectionParameters,
		config.Versions,
		verifySourceAddr,
		aeadChanged,
	)
	if err != nil {
		return nil, nil, err
	}

	s.packer = newPacketPacker(connectionID, s.cryptoSetup, s.connectionParameters, s.streamFramer, s.perspective, s.version)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}

	return s, handshakeChan, err
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	config *Config,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		config:       config,

		connectionParameters: handshake.NewConnectionParamatersManager(protocol.PerspectiveClient, v),
	}

	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(s.ackAlarmChanged)
	s.setup()

	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	cryptoStream, _ := s.OpenStream()
	var err error
	s.cryptoSetup, err = newCryptoSetupClient(
		hostname,
		connectionID,
		v,
		cryptoStream,
		config.TLSConfig,
		s.connectionParameters,
		aeadChanged,
		&handshake.TransportParameters{RequestConnectionIDTruncation: config.RequestConnectionIDTruncation},
		negotiatedVersions,
	)
	if err != nil {
		return nil, nil, err
	}

	s.packer = newPacketPacker(connectionID, s.cryptoSetup, s.connectionParameters, s.streamFramer, s.perspective, s.version)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}

	return s, handshakeChan, err
}

// setup is called from newSession and newClientSession and initializes values that are independent of the perspective
func (s *session) setup() {
	s.rttStats = &congestion.RTTStats{}
	flowControlManager := flowcontrol.NewFlowControlManager(s.connectionParameters, s.rttStats)

	sentPacketHandler := ackhandler.NewSentPacketHandler(s.rttStats)

	now := time.Now()

	s.sentPacketHandler = sentPacketHandler
	s.flowControlManager = flowControlManager
	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(s.ackAlarmChanged)

	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.aeadChanged = make(chan protocol.EncryptionLevel, 2)
	s.runClosed = make(chan struct{})
	s.handshakeCompleteChan = make(chan error, 1)

	s.timer = time.NewTimer(0)
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)
	s.streamFramer = newStreamFramer(s.streamsMap, s.flowControlManager)
}

// run the session main loop
func (s *session) run() error {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	aeadChanged := s.aeadChanged

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		select {
		case closeErr = <-s.closeChan:
			break runLoop
		case <-s.timer.C:
			s.timerRead = true
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err := s.handlePacketImpl(p)
			if err != nil {
				if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
					s.tryQueueingUndecryptablePacket(p)
					continue
				}
				s.close(err)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
		case l, ok := <-aeadChanged:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				s.handshakeComplete = true
				aeadChanged = nil // prevent this case from ever being selected again
				close(s.handshakeChan)
				close(s.handshakeCompleteChan)
			} else {
				if l == protocol.EncryptionForwardSecure {
					s.packer.SetForwardSecure()
				}
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}

		now := time.Now()
		if s.sentPacketHandler.GetAlarmTimeout().Before(now) {
			// This could cause packets to be retransmitted, so check it before trying
			// to send packets.
			s.sentPacketHandler.OnAlarm()
		}

		if err := s.sendPacket(); err != nil {
			s.close(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.close(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if now.Sub(s.lastNetworkActivityTime) >= s.idleTimeout() {
			s.close(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= protocol.MaxTimeForCryptoHandshake {
			s.close(qerr.Error(qerr.NetworkIdleTimeout, "Crypto handshake did not complete in time."))
		}
		s.garbageCollectStreams()
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeCompleteChan <- closeErr.err
		s.handshakeChan <- handshakeEvent{err: closeErr.err}
	}
	s.handleCloseError(closeErr)
	close(s.runClosed)
	return closeErr.err
}

func (s *session) maybeResetTimer() {
	nextDeadline := s.lastNetworkActivityTime.Add(s.idleTimeout())

	if !s.nextAckScheduledTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.nextAckScheduledTime)
	}
	if lossTime := s.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, lossTime)
	}
	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(protocol.MaxTimeForCryptoHandshake)
		nextDeadline = utils.MinTime(nextDeadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}

	if nextDeadline.Equal(s.currentDeadline) {
		// No need to reset the timer
		return
	}

	// We need to drain the timer if the value from its channel was not read yet.
	// See https://groups.google.com/forum/#!topic/golang-dev/c9UUfASVPoU
	if !s.timer.Stop() && !s.timerRead {
		<-s.timer.C
	}
	s.timer.Reset(nextDeadline.Sub(time.Now()))

	s.timerRead = false
	s.currentDeadline = nextDeadline
}

func (s *session) idleTimeout() time.Duration {
	if s.handshakeComplete {
		return s.connectionParameters.GetIdleConnectionStateLifetime()
	}
	return protocol.InitialIdleTimeout
}

func (s *session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.publicHeader.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.lastNetworkActivityTime = p.rcvTime
	hdr := p.publicHeader
	data := p.data

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, packet.encryptionLevel)
		}
	}
	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if s.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		s.conn.SetCurrentRemoteAddr(p.remoteAddr)
	}
	if err != nil {
		return err
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.IsRetransmittable())
	// ignore duplicate packets
	if err == ackhandler.ErrDuplicatePacket {
		utils.Infof("Ignoring packet 0x%x due to ErrDuplicatePacket", hdr.PacketNumber)
		return nil
	}
	// ignore packets with packet numbers smaller than the LeastUnacked of a StopWaiting
	if err == ackhandler.ErrPacketSmallerThanLastStopWaiting {
		utils.Infof("Ignoring packet 0x%x due to ErrPacketSmallerThanLastStopWaiting", hdr.PacketNumber)
		return nil
	}

	if err != nil {
		return err
	}

	return s.handleFrames(packet.frames)
}

func (s *session) handleFrames(fs []frames.Frame) error {
	for _, ff := range fs {
		var err error
		frames.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			err = s.handleAckFrame(frame)
		case *frames.ConnectionCloseFrame:
			s.registerClose(qerr.Error(frame.ErrorCode, frame.ReasonPhrase), true)
		case *frames.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *frames.StopWaitingFrame:
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
		case *frames.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

// handlePacket is called by the server with a new packet
func (s *session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *session) handleStreamFrame(frame *frames.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.AddStreamFrame(frame)
}

func (s *session) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	if frame.StreamID != 0 {
		str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
		if err != nil {
			return err
		}
		if str == nil {
			return errWindowUpdateOnClosedStream
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

func (s *session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}

	str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return s.flowControlManager.ResetStream(frame.StreamID, frame.ByteOffset)
}

func (s *session) handleAckFrame(frame *frames.AckFrame) error {
	return s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, s.lastNetworkActivityTime)
}

func (s *session) registerClose(e error, remoteClose bool) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return errSessionAlreadyClosed
	}

	if e == nil {
		e = qerr.PeerGoingAway
	}

	if e == errCloseSessionForNewVersion {
		s.streamsMap.CloseWithError(e)
		s.closeStreamsWithError(e)
	}

	s.closeChan <- closeError{err: e, remote: remoteClose}
	return nil
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	err := s.registerClose(e, false)
	if err == errSessionAlreadyClosed {
		return nil
	}

	// wait for the run loop to finish
	<-s.runClosed
	return err
}

// close the connection. Use this when called from the run loop
func (s *session) close(e error) error {
	err := s.registerClose(e, false)
	if err == errSessionAlreadyClosed {
		return nil
	}
	return err
}

func (s *session) handleCloseError(closeErr closeError) error {
	var quicErr *qerr.QuicError
	var ok bool
	if quicErr, ok = closeErr.err.(*qerr.QuicError); !ok {
		quicErr = qerr.ToQuicError(closeErr.err)
	}
	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", closeErr.err.Error())
	}

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	s.streamsMap.CloseWithError(quicErr)
	s.closeStreamsWithError(quicErr)

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure || quicErr == handshake.ErrHOLExperiment {
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *session) closeStreamsWithError(err error) {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		str.Cancel(err)
		return true, nil
	})
}

func (s *session) sendPacket() error {
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		if !s.sentPacketHandler.SendingAllowed() {
			return nil
		}

		var controlFrames []frames.Frame

		// get WindowUpdate frames
		// this call triggers the flow controller to increase the flow control windows, if necessary
		windowUpdateFrames := s.getWindowUpdateFrames()
		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}
			utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)

			if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
				utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				stopWaitingFrame := s.sentPacketHandler.GetStopWaitingFrame(true)
				var packet *packedPacket
				packet, err := s.packer.RetransmitNonForwardSecurePacket(stopWaitingFrame, retransmitPacket)
				if err != nil {
					return err
				}
				if packet == nil {
					continue
				}
				err = s.sendPackedPacket(packet)
				if err != nil {
					return err
				}
				continue
			} else {
				// resend the frames that were in the packet
				for _, frame := range retransmitPacket.GetFramesForRetransmission() {
					switch frame.(type) {
					case *frames.StreamFrame:
						s.streamFramer.AddFrameForRetransmission(frame.(*frames.StreamFrame))
					case *frames.WindowUpdateFrame:
						// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
						var currentOffset protocol.ByteCount
						f := frame.(*frames.WindowUpdateFrame)
						currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
						if err == nil && f.ByteOffset >= currentOffset {
							controlFrames = append(controlFrames, frame)
						}
					default:
						controlFrames = append(controlFrames, frame)
					}
				}
			}
		}

		ack := s.receivedPacketHandler.GetAckFrame()
		if ack != nil {
			controlFrames = append(controlFrames, ack)
		}
		hasRetransmission := s.streamFramer.HasFramesForRetransmission()
		var stopWaitingFrame *frames.StopWaitingFrame
		if ack != nil || hasRetransmission {
			stopWaitingFrame = s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
		}
		packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, s.sentPacketHandler.GetLeastUnacked())
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		// send every window update twice
		for _, f := range windowUpdateFrames {
			s.packer.QueueControlFrameForNextPacket(f)
		}

		err = s.sendPackedPacket(packet)
		if err != nil {
			return err
		}
		s.nextAckScheduledTime = time.Time{}
	}
}

func (s *session) sendPackedPacket(packet *packedPacket) error {
	err := s.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	})
	if err != nil {
		return err
	}

	s.logPacket(packet)

	err = s.conn.Write(packet.raw)
	putPacketBuffer(packet.raw)
	return err
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage}, s.sentPacketHandler.GetLeastUnacked())
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected packet not to be nil")
	}
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *session) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	if utils.Debug() {
		utils.Debugf("-> Sending packet 0x%x (%d bytes), %s", packet.number, len(packet.raw), packet.encryptionLevel)
		for _, frame := range packet.frames {
			frames.LogFrame(frame, true)
		}
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenStream(id)
	if str != nil {
		return str, err
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) WaitUntilHandshakeComplete() error {
	return <-s.handshakeCompleteChan
}

func (s *session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.packer.QueueControlFrameForNextPacket(&frames.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending()
}

func (s *session) newStream(id protocol.StreamID) (*stream, error) {
	stream, err := newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
	if err != nil {
		return nil, err
	}

	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}

	return stream, nil
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *session) garbageCollectStreams() {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		id := str.StreamID()
		if str.finished() {
			err := s.streamsMap.RemoveStream(id)
			if err != nil {
				return false, err
			}
			s.flowControlManager.RemoveStream(id)
		}
		return true, nil
	})
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.Write(writePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.handshakeComplete {
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.publicHeader.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) getWindowUpdateFrames() []*frames.WindowUpdateFrame {
	updates := s.flowControlManager.GetWindowUpdates()
	res := make([]*frames.WindowUpdateFrame, len(updates))
	for i, u := range updates {
		res[i] = &frames.WindowUpdateFrame{StreamID: u.StreamID, ByteOffset: u.Offset}
	}
	return res
}

func (s *session) ackAlarmChanged(t time.Time) {
	s.nextAckScheduledTime = t
	s.maybeResetTimer()
}

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
