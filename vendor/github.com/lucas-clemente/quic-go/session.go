package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type unpacker interface {
	Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error)
}

type streamGetter interface {
	GetOrOpenReceiveStream(protocol.StreamID) (receiveStreamI, error)
	GetOrOpenSendStream(protocol.StreamID) (sendStreamI, error)
}

type streamManager interface {
	GetOrOpenSendStream(protocol.StreamID) (sendStreamI, error)
	GetOrOpenReceiveStream(protocol.StreamID) (receiveStreamI, error)
	OpenStream() (Stream, error)
	OpenUniStream() (SendStream, error)
	OpenStreamSync() (Stream, error)
	OpenUniStreamSync() (SendStream, error)
	AcceptStream() (Stream, error)
	AcceptUniStream() (ReceiveStream, error)
	DeleteStream(protocol.StreamID) error
	UpdateLimits(*handshake.TransportParameters)
	HandleMaxStreamIDFrame(*wire.MaxStreamIDFrame) error
	CloseWithError(error)
}

type receivedPacket struct {
	remoteAddr net.Addr
	header     *wire.Header
	data       []byte
	rcvTime    time.Time
}

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

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

	streamsMap   streamManager
	cryptoStream cryptoStreamI

	rttStats *congestion.RTTStats

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	streamFramer          *streamFramer
	windowUpdateQueue     *windowUpdateQueue
	connFlowController    flowcontrol.ConnectionFlowController

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	closeOnce sync.Once

	ctx       context.Context
	ctxCancel context.CancelFunc

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the transport parameters, as soon as the peer sends them
	paramsChan <-chan handshake.TransportParameters
	// the handshakeEvent channel is passed to the CryptoSetup.
	// It receives when it makes sense to try decrypting undecryptable packets.
	handshakeEvent <-chan struct{}
	// handshakeChan is returned by handshakeStatus.
	// It receives any error that might occur during the handshake.
	// It is closed when the handshake is complete.
	handshakeChan     chan error
	handshakeComplete bool

	receivedFirstPacket              bool // since packet numbers start at 0, we can't use largestRcvdPacketNumber != 0 for this
	receivedFirstForwardSecurePacket bool
	lastRcvdPacketNumber             protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	largestRcvdPacketNumber protocol.PacketNumber

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time
	// pacingDeadline is the time when the next packet should be sent
	pacingDeadline time.Time

	peerParams *handshake.TransportParameters

	timer *utils.Timer
	// keepAlivePingSent stores whether a Ping frame was sent to the peer or not
	// it is reset as soon as we receive a packet from the peer
	keepAlivePingSent bool
}

var _ Session = &session{}
var _ streamSender = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	scfg *handshake.ServerConfig,
	tlsConf *tls.Config,
	config *Config,
) (packetHandler, error) {
	paramsChan := make(chan handshake.TransportParameters)
	handshakeEvent := make(chan struct{}, 1)
	s := &session{
		conn:           conn,
		connectionID:   connectionID,
		perspective:    protocol.PerspectiveServer,
		version:        v,
		config:         config,
		handshakeEvent: handshakeEvent,
		paramsChan:     paramsChan,
	}
	s.preSetup()
	transportParams := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		MaxStreams:                  uint32(s.config.MaxIncomingStreams),
		IdleTimeout:                 s.config.IdleTimeout,
	}
	cs, err := newCryptoSetup(
		s.cryptoStream,
		s.connectionID,
		s.conn.RemoteAddr(),
		s.version,
		scfg,
		transportParams,
		s.config.Versions,
		s.config.AcceptCookie,
		paramsChan,
		handshakeEvent,
	)
	if err != nil {
		return nil, err
	}
	s.cryptoSetup = cs
	return s, s.postSetup(1)
}

// declare this as a variable, so that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	tlsConf *tls.Config,
	config *Config,
	initialVersion protocol.VersionNumber,
	negotiatedVersions []protocol.VersionNumber, // needed for validation of the GQUIC version negotiation
) (packetHandler, error) {
	paramsChan := make(chan handshake.TransportParameters)
	handshakeEvent := make(chan struct{}, 1)
	s := &session{
		conn:           conn,
		connectionID:   connectionID,
		perspective:    protocol.PerspectiveClient,
		version:        v,
		config:         config,
		handshakeEvent: handshakeEvent,
		paramsChan:     paramsChan,
	}
	s.preSetup()
	transportParams := &handshake.TransportParameters{
		StreamFlowControlWindow:     protocol.ReceiveStreamFlowControlWindow,
		ConnectionFlowControlWindow: protocol.ReceiveConnectionFlowControlWindow,
		MaxStreams:                  uint32(s.config.MaxIncomingStreams),
		IdleTimeout:                 s.config.IdleTimeout,
		OmitConnectionID:            s.config.RequestConnectionIDOmission,
	}
	cs, err := newCryptoSetupClient(
		s.cryptoStream,
		hostname,
		s.connectionID,
		s.version,
		tlsConf,
		transportParams,
		paramsChan,
		handshakeEvent,
		initialVersion,
		negotiatedVersions,
	)
	if err != nil {
		return nil, err
	}
	s.cryptoSetup = cs
	return s, s.postSetup(1)
}

func newTLSServerSession(
	conn connection,
	connectionID protocol.ConnectionID,
	initialPacketNumber protocol.PacketNumber,
	config *Config,
	tls handshake.MintTLS,
	cryptoStreamConn *handshake.CryptoStreamConn,
	nullAEAD crypto.AEAD,
	peerParams *handshake.TransportParameters,
	v protocol.VersionNumber,
) (packetHandler, error) {
	handshakeEvent := make(chan struct{}, 1)
	s := &session{
		conn:           conn,
		config:         config,
		connectionID:   connectionID,
		perspective:    protocol.PerspectiveServer,
		version:        v,
		handshakeEvent: handshakeEvent,
	}
	s.preSetup()
	s.cryptoSetup = handshake.NewCryptoSetupTLSServer(
		tls,
		cryptoStreamConn,
		nullAEAD,
		handshakeEvent,
		v,
	)
	if err := s.postSetup(initialPacketNumber); err != nil {
		return nil, err
	}
	s.peerParams = peerParams
	s.processTransportParameters(peerParams)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}
	return s, nil
}

// declare this as a variable, such that we can it mock it in the tests
var newTLSClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	config *Config,
	tls handshake.MintTLS,
	paramsChan <-chan handshake.TransportParameters,
	initialPacketNumber protocol.PacketNumber,
) (packetHandler, error) {
	handshakeEvent := make(chan struct{}, 1)
	s := &session{
		conn:           conn,
		config:         config,
		connectionID:   connectionID,
		perspective:    protocol.PerspectiveClient,
		version:        v,
		handshakeEvent: handshakeEvent,
		paramsChan:     paramsChan,
	}
	s.preSetup()
	tls.SetCryptoStream(s.cryptoStream)
	cs, err := handshake.NewCryptoSetupTLSClient(
		s.cryptoStream,
		s.connectionID,
		hostname,
		handshakeEvent,
		tls,
		v,
	)
	if err != nil {
		return nil, err
	}
	s.cryptoSetup = cs
	return s, s.postSetup(initialPacketNumber)
}

func (s *session) preSetup() {
	s.rttStats = &congestion.RTTStats{}
	s.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.ReceiveConnectionFlowControlWindow,
		protocol.ByteCount(s.config.MaxReceiveConnectionFlowControlWindow),
		s.rttStats,
	)
	s.cryptoStream = s.newCryptoStream()
}

func (s *session) postSetup(initialPacketNumber protocol.PacketNumber) error {
	s.handshakeChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.timer = utils.NewTimer()
	now := time.Now()
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.sentPacketHandler = ackhandler.NewSentPacketHandler(s.rttStats)
	s.receivedPacketHandler = ackhandler.NewReceivedPacketHandler(s.rttStats, s.version)

	if s.version.UsesTLS() {
		s.streamsMap = newStreamsMap(s, s.newFlowController, s.config.MaxIncomingStreams, s.config.MaxIncomingUniStreams, s.perspective, s.version)
	} else {
		s.streamsMap = newStreamsMapLegacy(s.newStream, s.config.MaxIncomingStreams, s.perspective)
	}
	s.streamFramer = newStreamFramer(s.cryptoStream, s.streamsMap, s.version)
	s.packer = newPacketPacker(s.connectionID,
		initialPacketNumber,
		s.sentPacketHandler.GetPacketNumberLen,
		s.RemoteAddr(),
		s.cryptoSetup,
		s.streamFramer,
		s.perspective,
		s.version,
	)
	s.windowUpdateQueue = newWindowUpdateQueue(s.streamsMap, s.cryptoStream, s.packer.QueueControlFrame)
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version}
	return nil
}

// run the session main loop
func (s *session) run() error {
	defer s.ctxCancel()

	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	handshakeEvent := s.handshakeEvent

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
			putPacketBuffer(&p.header.Raw)
		case p := <-s.paramsChan:
			s.processTransportParameters(&p)
		case _, ok := <-handshakeEvent:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				s.handshakeComplete = true
				handshakeEvent = nil // prevent this case from ever being selected again
				if !s.version.UsesTLS() && s.perspective == protocol.PerspectiveClient {
					// In gQUIC, there's no equivalent to the Finished message in TLS
					// The server knows that the handshake is complete when it receives the first forward-secure packet sent by the client.
					// We need to make sure that the client actually sends such a packet.
					s.packer.QueueControlFrame(&wire.PingFrame{})
				}
				close(s.handshakeChan)
			} else {
				s.tryDecryptingQueuedPackets()
			}
		}

		now := time.Now()
		if timeout := s.sentPacketHandler.GetAlarmTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted.
			// Check it before trying to send packets.
			if err := s.sentPacketHandler.OnAlarm(); err != nil {
				s.closeLocal(err)
			}
		}

		var pacingDeadline time.Time
		if s.pacingDeadline.IsZero() { // the timer didn't have a pacing deadline set
			pacingDeadline = s.sentPacketHandler.TimeUntilSend()
		}
		if s.config.KeepAlive && !s.keepAlivePingSent && s.handshakeComplete && time.Since(s.lastNetworkActivityTime) >= s.peerParams.IdleTimeout/2 {
			// send the PING frame since there is no activity in the session
			s.packer.QueueControlFrame(&wire.PingFrame{})
			s.keepAlivePingSent = true
		} else if !pacingDeadline.IsZero() && now.Before(pacingDeadline) {
			// If we get to this point before the pacing deadline, we should wait until that deadline.
			// This can happen when scheduleSending is called, or a packet is received.
			// Set the timer and restart the run loop.
			s.pacingDeadline = pacingDeadline
			continue
		}

		if err := s.sendPackets(); err != nil {
			s.closeLocal(err)
		}

		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
		}
		if s.handshakeComplete && now.Sub(s.lastNetworkActivityTime) >= s.config.IdleTimeout {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeChan <- closeErr.err
	}
	s.handleCloseError(closeErr)
	return closeErr.err
}

func (s *session) Context() context.Context {
	return s.ctx
}

func (s *session) ConnectionState() ConnectionState {
	return s.cryptoSetup.ConnectionState()
}

func (s *session) maybeResetTimer() {
	var deadline time.Time
	if s.config.KeepAlive && s.handshakeComplete && !s.keepAlivePingSent {
		deadline = s.lastNetworkActivityTime.Add(s.peerParams.IdleTimeout / 2)
	} else {
		deadline = s.lastNetworkActivityTime.Add(s.config.IdleTimeout)
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
	if !s.pacingDeadline.IsZero() {
		deadline = utils.MinTime(deadline, s.pacingDeadline)
	}

	s.timer.Reset(deadline)
}

func (s *session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.header.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.receivedFirstPacket = true
	s.lastNetworkActivityTime = p.rcvTime
	s.keepAlivePingSent = false
	hdr := p.header
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
		hdr.Log()
	}
	// if the decryption failed, this might be a packet sent by an attacker
	if err != nil {
		return err
	}

	// In TLS 1.3, the client considers the handshake complete as soon as
	// it received the server's Finished message and sent its Finished.
	// We have to wait for the first forward-secure packet from the server before
	// deleting all handshake packets from the history.
	if !s.receivedFirstForwardSecurePacket && packet.encryptionLevel == protocol.EncryptionForwardSecure {
		s.receivedFirstForwardSecurePacket = true
		s.sentPacketHandler.SetHandshakeComplete()
	}

	s.lastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	s.largestRcvdPacketNumber = utils.MaxPacketNumber(s.largestRcvdPacketNumber, hdr.PacketNumber)

	// If this is a Retry packet, there's no need to send an ACK.
	// The session will be closed and recreated as soon as the crypto setup processed the HRR.
	if hdr.Type != protocol.PacketTypeRetry {
		isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
		if err := s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, p.rcvTime, isRetransmittable); err != nil {
			return err
		}
	}

	return s.handleFrames(packet.frames, packet.encryptionLevel)
}

func (s *session) handleFrames(fs []wire.Frame, encLevel protocol.EncryptionLevel) error {
	for _, ff := range fs {
		var err error
		wire.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *wire.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *wire.AckFrame:
			err = s.handleAckFrame(frame, encLevel)
		case *wire.ConnectionCloseFrame:
			s.closeRemote(qerr.Error(frame.ErrorCode, frame.ReasonPhrase))
		case *wire.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *wire.StopWaitingFrame: // ignore STOP_WAITINGs
		case *wire.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *wire.MaxDataFrame:
			s.handleMaxDataFrame(frame)
		case *wire.MaxStreamDataFrame:
			err = s.handleMaxStreamDataFrame(frame)
		case *wire.MaxStreamIDFrame:
			err = s.handleMaxStreamIDFrame(frame)
		case *wire.BlockedFrame:
		case *wire.StreamBlockedFrame:
		case *wire.StreamIDBlockedFrame:
		case *wire.StopSendingFrame:
			err = s.handleStopSendingFrame(frame)
		case *wire.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			return err
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

func (s *session) handleStreamFrame(frame *wire.StreamFrame) error {
	if frame.StreamID == s.version.CryptoStreamID() {
		if frame.FinBit {
			return errors.New("Received STREAM frame with FIN bit for the crypto stream")
		}
		return s.cryptoStream.handleStreamFrame(frame)
	}
	str, err := s.streamsMap.GetOrOpenReceiveStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.handleStreamFrame(frame)
}

func (s *session) handleMaxDataFrame(frame *wire.MaxDataFrame) {
	s.connFlowController.UpdateSendWindow(frame.ByteOffset)
}

func (s *session) handleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) error {
	if frame.StreamID == s.version.CryptoStreamID() {
		s.cryptoStream.handleMaxStreamDataFrame(frame)
		return nil
	}
	str, err := s.streamsMap.GetOrOpenSendStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	str.handleMaxStreamDataFrame(frame)
	return nil
}

func (s *session) handleMaxStreamIDFrame(frame *wire.MaxStreamIDFrame) error {
	return s.streamsMap.HandleMaxStreamIDFrame(frame)
}

func (s *session) handleRstStreamFrame(frame *wire.RstStreamFrame) error {
	if frame.StreamID == s.version.CryptoStreamID() {
		return errors.New("Received RST_STREAM frame for the crypto stream")
	}
	str, err := s.streamsMap.GetOrOpenReceiveStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	return str.handleRstStreamFrame(frame)
}

func (s *session) handleStopSendingFrame(frame *wire.StopSendingFrame) error {
	if frame.StreamID == s.version.CryptoStreamID() {
		return errors.New("Received a STOP_SENDING frame for the crypto stream")
	}
	str, err := s.streamsMap.GetOrOpenSendStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	str.handleStopSendingFrame(frame)
	return nil
}

func (s *session) handleAckFrame(frame *wire.AckFrame, encLevel protocol.EncryptionLevel) error {
	if err := s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber, encLevel, s.lastNetworkActivityTime); err != nil {
		return err
	}
	s.receivedPacketHandler.IgnoreBelow(s.sentPacketHandler.GetLowestPacketNotConfirmedAcked())
	return nil
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
	<-s.ctx.Done()
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

	s.cryptoStream.closeForShutdown(quicErr)
	s.streamsMap.CloseWithError(quicErr)

	if closeErr.err == errCloseSessionForNewVersion || closeErr.err == handshake.ErrCloseSessionForRetry {
		return nil
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure ||
		quicErr == handshake.ErrHOLExperiment ||
		quicErr == handshake.ErrNSTPExperiment {
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *session) processTransportParameters(params *handshake.TransportParameters) {
	s.peerParams = params
	s.streamsMap.UpdateLimits(params)
	if params.OmitConnectionID {
		s.packer.SetOmitConnectionID()
	}
	if params.MaxPacketSize != 0 {
		s.packer.SetMaxPacketSize(params.MaxPacketSize)
	}
	s.connFlowController.UpdateSendWindow(params.ConnectionFlowControlWindow)
	// the crypto stream is the only open stream at this moment
	// so we don't need to update stream flow control windows
}

func (s *session) sendPackets() error {
	s.pacingDeadline = time.Time{}

	sendMode := s.sentPacketHandler.SendMode()
	if sendMode == ackhandler.SendNone { // shortcut: return immediately if there's nothing to send
		return nil
	}

	numPackets := s.sentPacketHandler.ShouldSendNumPackets()
	var numPacketsSent int
sendLoop:
	for {
		switch sendMode {
		case ackhandler.SendNone:
			break sendLoop
		case ackhandler.SendAck:
			// We can at most send a single ACK only packet.
			// There will only be a new ACK after receiving new packets.
			// SendAck is only returned when we're congestion limited, so we don't need to set the pacingt timer.
			return s.maybeSendAckOnlyPacket()
		case ackhandler.SendRetransmission:
			sentPacket, err := s.maybeSendRetransmission()
			if err != nil {
				return err
			}
			if sentPacket {
				numPacketsSent++
				// This can happen if a retransmission queued, but it wasn't necessary to send it.
				// e.g. when an Initial is queued, but we already received a packet from the server.
			}
		case ackhandler.SendAny:
			sentPacket, err := s.sendPacket()
			if err != nil {
				return err
			}
			if !sentPacket {
				break sendLoop
			}
			numPacketsSent++
		default:
			return fmt.Errorf("BUG: invalid send mode %d", sendMode)
		}
		if numPacketsSent >= numPackets {
			break
		}
		sendMode = s.sentPacketHandler.SendMode()
	}
	// Only start the pacing timer if we sent as many packets as we were allowed.
	// There will probably be more to send when calling sendPacket again.
	if numPacketsSent == numPackets {
		s.pacingDeadline = s.sentPacketHandler.TimeUntilSend()
	}
	return nil
}

func (s *session) maybeSendAckOnlyPacket() error {
	ack := s.receivedPacketHandler.GetAckFrame()
	if ack == nil {
		return nil
	}
	s.packer.QueueControlFrame(ack)

	if s.version.UsesStopWaitingFrames() { // for gQUIC, maybe add a STOP_WAITING
		if swf := s.sentPacketHandler.GetStopWaitingFrame(false); swf != nil {
			s.packer.QueueControlFrame(swf)
		}
	}
	packet, err := s.packer.PackAckPacket()
	if err != nil {
		return err
	}
	s.sentPacketHandler.SentPacket(packet.ToAckHandlerPacket())
	return s.sendPackedPacket(packet)
}

// maybeSendRetransmission sends retransmissions for at most one packet.
// It takes care that Initials aren't retransmitted, if a packet from the server was already received.
func (s *session) maybeSendRetransmission() (bool, error) {
	var retransmitPacket *ackhandler.Packet
	for {
		retransmitPacket = s.sentPacketHandler.DequeuePacketForRetransmission()
		if retransmitPacket == nil {
			return false, nil
		}

		// Don't retransmit Initial packets if we already received a response.
		// An Initial might have been retransmitted multiple times before we receive a response.
		// As soon as we receive one response, we don't need to send any more Initials.
		if s.receivedFirstPacket && retransmitPacket.PacketType == protocol.PacketTypeInitial {
			utils.Debugf("Skipping retransmission of packet %d. Already received a response to an Initial.", retransmitPacket.PacketNumber)
			continue
		}
		break
	}

	if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
		utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
	} else {
		utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)
	}

	if s.version.UsesStopWaitingFrames() {
		s.packer.QueueControlFrame(s.sentPacketHandler.GetStopWaitingFrame(true))
	}
	packets, err := s.packer.PackRetransmission(retransmitPacket)
	if err != nil {
		return false, err
	}
	ackhandlerPackets := make([]*ackhandler.Packet, len(packets))
	for i, packet := range packets {
		ackhandlerPackets[i] = packet.ToAckHandlerPacket()
	}
	s.sentPacketHandler.SentPacketsAsRetransmission(ackhandlerPackets, retransmitPacket.PacketNumber)
	for _, packet := range packets {
		if err := s.sendPackedPacket(packet); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (s *session) sendPacket() (bool, error) {
	if offset := s.connFlowController.GetWindowUpdate(); offset != 0 {
		s.packer.QueueControlFrame(&wire.MaxDataFrame{ByteOffset: offset})
	}
	if isBlocked, offset := s.connFlowController.IsNewlyBlocked(); isBlocked {
		s.packer.QueueControlFrame(&wire.BlockedFrame{Offset: offset})
	}
	s.windowUpdateQueue.QueueAll()

	if ack := s.receivedPacketHandler.GetAckFrame(); ack != nil {
		s.packer.QueueControlFrame(ack)
		if s.version.UsesStopWaitingFrames() {
			if swf := s.sentPacketHandler.GetStopWaitingFrame(false); swf != nil {
				s.packer.QueueControlFrame(swf)
			}
		}
	}

	packet, err := s.packer.PackPacket()
	if err != nil || packet == nil {
		return false, err
	}
	s.sentPacketHandler.SentPacket(packet.ToAckHandlerPacket())
	if err := s.sendPackedPacket(packet); err != nil {
		return false, err
	}
	return true, nil
}

func (s *session) sendPackedPacket(packet *packedPacket) error {
	defer putPacketBuffer(&packet.raw)
	s.logPacket(packet)
	return s.conn.Write(packet.raw)
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&wire.ConnectionCloseFrame{
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
	utils.Debugf("-> Sending packet 0x%x (%d bytes) for connection %x, %s", packet.header.PacketNumber, len(packet.raw), s.connectionID, packet.encryptionLevel)
	packet.header.Log()
	for _, frame := range packet.frames {
		wire.LogFrame(frame, true)
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// It is *only* needed for gQUIC's H2.
// It will be removed as soon as gQUIC moves towards the IETF H2/QUIC stream mapping.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenSendStream(id)
	if str != nil {
		if bstr, ok := str.(Stream); ok {
			return bstr, err
		}
		return nil, fmt.Errorf("Stream %d is not a bidirectional stream", id)
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

func (s *session) AcceptUniStream() (ReceiveStream, error) {
	return s.streamsMap.AcceptUniStream()
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) OpenUniStream() (SendStream, error) {
	return s.streamsMap.OpenUniStream()
}

func (s *session) OpenUniStreamSync() (SendStream, error) {
	return s.streamsMap.OpenUniStreamSync()
}

func (s *session) newStream(id protocol.StreamID) streamI {
	flowController := s.newFlowController(id)
	return newStream(id, s, flowController, s.version)
}

func (s *session) newFlowController(id protocol.StreamID) flowcontrol.StreamFlowController {
	var initialSendWindow protocol.ByteCount
	if s.peerParams != nil {
		initialSendWindow = s.peerParams.StreamFlowControlWindow
	}
	return flowcontrol.NewStreamFlowController(
		id,
		s.version.StreamContributesToConnectionFlowControl(id),
		s.connFlowController,
		protocol.ReceiveStreamFlowControlWindow,
		protocol.ByteCount(s.config.MaxReceiveStreamFlowControlWindow),
		initialSendWindow,
		s.rttStats,
	)
}

func (s *session) newCryptoStream() cryptoStreamI {
	id := s.version.CryptoStreamID()
	flowController := flowcontrol.NewStreamFlowController(
		id,
		s.version.StreamContributesToConnectionFlowControl(id),
		s.connFlowController,
		protocol.ReceiveStreamFlowControlWindow,
		protocol.ByteCount(s.config.MaxReceiveStreamFlowControlWindow),
		0,
		s.rttStats,
	)
	return newCryptoStream(s, flowController, s.version)
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.Write(wire.WritePublicReset(s.connectionID, rejectedPacketNumber, 0))
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
		utils.Debugf("Received undecryptable packet from %s after the handshake: %#v, %d bytes data", p.remoteAddr.String(), p.header, len(p.data))
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.header.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.header.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) queueControlFrame(f wire.Frame) {
	s.packer.QueueControlFrame(f)
	s.scheduleSending()
}

func (s *session) onHasWindowUpdate(id protocol.StreamID) {
	s.windowUpdateQueue.Add(id)
	s.scheduleSending()
}

func (s *session) onHasStreamData(id protocol.StreamID) {
	s.streamFramer.AddActiveStream(id)
	s.scheduleSending()
}

func (s *session) onStreamCompleted(id protocol.StreamID) {
	if err := s.streamsMap.DeleteStream(id); err != nil {
		s.Close(err)
	}
}

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *session) handshakeStatus() <-chan error {
	return s.handshakeChan
}

func (s *session) getCryptoStream() cryptoStreamI {
	return s.cryptoStream
}

func (s *session) GetVersion() protocol.VersionNumber {
	return s.version
}
