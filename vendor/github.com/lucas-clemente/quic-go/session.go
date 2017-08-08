package quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
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
	tlsConf      *tls.Config
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
	// runClosed is closed once the run loop exits
	// it is used to block Close() and WaitUntilClosed()
	runClosed chan struct{}
	closeOnce sync.Once

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

	connectionParameters handshake.ConnectionParametersManager

	lastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time

	timer *utils.Timer
	// keepAlivePingSent stores whether a Ping frame was sent to the peer or not
	// it is reset as soon as we receive a packet from the peer
	keepAlivePingSent bool
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	tlsConf *tls.Config,
	config *Config,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,
	}
	return s.setup(sCfg, "", nil)
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	tlsConf *tls.Config,
	config *Config,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		tlsConf:      tlsConf,
		config:       config,
	}
	return s.setup(nil, hostname, negotiatedVersions)
}

func (s *session) setup(
	scfg *handshake.ServerConfig,
	hostname string,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	s.runClosed = make(chan struct{})
	s.handshakeCompleteChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)

	s.timer = utils.NewTimer()
	now := time.Now()
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.rttStats = &congestion.RTTStats{}
	s.connectionParameters = handshake.NewConnectionParamatersManager(s.perspective, s.version,
		s.config.MaxReceiveStreamFlowControlWindow, s.config.MaxReceiveConnectionFlowControlWindow)
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(s.rttStats)
	s.flowControlManager = flowcontrol.NewFlowControlManager(s.connectionParameters, s.rttStats)
	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler()
	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)
	s.streamFramer = newStreamFramer(s.streamsMap, s.flowControlManager)

	var err error
	if s.perspective == protocol.PerspectiveServer {
		cryptoStream, _ := s.GetOrOpenStream(1)
		_, _ = s.AcceptStream() // don't expose the crypto stream
		verifySourceAddr := func(clientAddr net.Addr, hstk *handshake.STK) bool {
			var stk *STK
			if hstk != nil {
				stk = &STK{remoteAddr: hstk.RemoteAddr, sentTime: hstk.SentTime}
			}
			return s.config.AcceptSTK(clientAddr, stk)
		}
		s.cryptoSetup, err = newCryptoSetup(
			s.connectionID,
			s.conn.RemoteAddr(),
			s.version,
			scfg,
			cryptoStream,
			s.connectionParameters,
			s.config.Versions,
			verifySourceAddr,
			aeadChanged,
		)
	} else {
		cryptoStream, _ := s.OpenStream()
		s.cryptoSetup, err = newCryptoSetupClient(
			hostname,
			s.connectionID,
			s.version,
			cryptoStream,
			s.tlsConf,
			s.connectionParameters,
			aeadChanged,
			&handshake.TransportParameters{RequestConnectionIDTruncation: s.config.RequestConnectionIDTruncation},
			negotiatedVersions,
		)
	}
	if err != nil {
		return nil, nil, err
	}

	s.packer = newPacketPacker(s.connectionID,
		s.cryptoSetup,
		s.connectionParameters,
		s.streamFramer,
		s.perspective,
		s.version,
	)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}

	return s, handshakeChan, nil
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
		case <-s.timer.Chan():
			s.timer.SetRead()
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
				s.closeLocal(err)
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
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}

		now := time.Now()
		if timeout := s.sentPacketHandler.GetAlarmTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted, so check it before trying
			// to send packets.
			s.sentPacketHandler.OnAlarm()
		}

		if s.config.KeepAlive && s.handshakeComplete && time.Since(s.lastNetworkActivityTime) >= s.idleTimeout()/2 {
			// send the PING frame since there is no activity in the session
			s.packer.QueueControlFrame(&frames.PingFrame{})
			s.keepAlivePingSent = true
		}

		if err := s.sendPacket(); err != nil {
			s.closeLocal(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if now.Sub(s.lastNetworkActivityTime) >= s.idleTimeout() {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
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

func (s *session) WaitUntilClosed() {
	<-s.runClosed
}

func (s *session) maybeResetTimer() {
	var deadline time.Time
	if s.config.KeepAlive && s.handshakeComplete && !s.keepAlivePingSent {
		deadline = s.lastNetworkActivityTime.Add(s.idleTimeout() / 2)
	} else {
		deadline = s.lastNetworkActivityTime.Add(s.idleTimeout())
	}

	if ackAlarm := s.receivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = utils.MinTime(deadline, ackAlarm)
	}
	if lossTime := s.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}
	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(s.config.HandshakeTimeout)
		deadline = utils.MinTime(deadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		deadline = utils.MinTime(deadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}

	s.timer.Reset(deadline)
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
	s.keepAlivePingSent = false
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

	isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
	if err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable); err != nil {
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
			s.closeRemote(qerr.Error(frame.ErrorCode, frame.ReasonPhrase))
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

func (s *session) closeLocal(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: false}
	})
}

func (s *session) closeRemote(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: true}
	})
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	s.closeLocal(e)
	<-s.runClosed
	return nil
}

func (s *session) handleCloseError(closeErr closeError) error {
	if closeErr.err == nil {
		closeErr.err = qerr.PeerGoingAway
	}

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

	s.streamsMap.CloseWithError(quicErr)

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure || quicErr == handshake.ErrHOLExperiment {
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *session) sendPacket() error {
	s.packer.SetLeastUnacked(s.sentPacketHandler.GetLeastUnacked())

	// Get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames()
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf)
	}

	ack := s.receivedPacketHandler.GetAckFrame()
	if ack != nil {
		s.packer.QueueControlFrame(ack)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		if !s.sentPacketHandler.SendingAllowed() {
			if ack == nil {
				return nil
			}
			// If we aren't allowed to send, at least try sending an ACK frame
			swf := s.sentPacketHandler.GetStopWaitingFrame(false)
			if swf != nil {
				s.packer.QueueControlFrame(swf)
			}
			packet, err := s.packer.PackAckPacket()
			if err != nil {
				return err
			}
			return s.sendPackedPacket(packet)
		}

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}

			if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
				if s.handshakeComplete {
					// Don't retransmit handshake packets when the handshake is complete
					continue
				}
				utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				s.packer.QueueControlFrame(s.sentPacketHandler.GetStopWaitingFrame(true))
				packet, err := s.packer.PackHandshakeRetransmission(retransmitPacket)
				if err != nil {
					return err
				}
				if err = s.sendPackedPacket(packet); err != nil {
					return err
				}
			} else {
				utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)
				// resend the frames that were in the packet
				for _, frame := range retransmitPacket.GetFramesForRetransmission() {
					switch f := frame.(type) {
					case *frames.StreamFrame:
						s.streamFramer.AddFrameForRetransmission(f)
					case *frames.WindowUpdateFrame:
						// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
						currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
						if err == nil && f.ByteOffset >= currentOffset {
							s.packer.QueueControlFrame(f)
						}
					default:
						s.packer.QueueControlFrame(frame)
					}
				}
			}
		}

		hasRetransmission := s.streamFramer.HasFramesForRetransmission()
		if ack != nil || hasRetransmission {
			swf := s.sentPacketHandler.GetStopWaitingFrame(hasRetransmission)
			if swf != nil {
				s.packer.QueueControlFrame(swf)
			}
		}
		packet, err := s.packer.PackPacket()
		if err != nil || packet == nil {
			return err
		}
		if err = s.sendPackedPacket(packet); err != nil {
			return err
		}

		// send every window update twice
		for _, f := range windowUpdateFrames {
			s.packer.QueueControlFrame(f)
		}
		windowUpdateFrames = nil
		ack = nil
	}
}

func (s *session) sendPackedPacket(packet *packedPacket) error {
	defer putPacketBuffer(packet.raw)
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
	return s.conn.Write(packet.raw)
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError) error {
	s.packer.SetLeastUnacked(s.sentPacketHandler.GetLeastUnacked())
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{
		ErrorCode:    quicErr.ErrorCode,
		ReasonPhrase: quicErr.ErrorMessage,
	})
	if err != nil {
		return err
	}
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *session) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	utils.Debugf("-> Sending packet 0x%x (%d bytes) for connection %x, %s", packet.number, len(packet.raw), s.connectionID, packet.encryptionLevel)
	for _, frame := range packet.frames {
		frames.LogFrame(frame, true)
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
	s.packer.QueueControlFrame(&frames.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending()
}

func (s *session) newStream(id protocol.StreamID) *stream {
	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}
	return newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
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
		utils.Debugf("Received undecryptable packet from %s after the handshake: %#v, %d bytes data", p.remoteAddr.String(), p.publicHeader, len(p.data))
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

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
