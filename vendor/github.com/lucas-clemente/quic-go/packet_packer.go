package quic

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type packedPacket struct {
	number          protocol.PacketNumber
	raw             []byte
	frames          []frames.Frame
	encryptionLevel protocol.EncryptionLevel
}

type packetPacker struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	cryptoSetup  handshake.CryptoSetup
	// as long as packets are not sent with forward-secure encryption, we limit the MaxPacketSize such that they can be retransmitted as a whole
	isForwardSecure bool

	packetNumberGenerator *packetNumberGenerator

	connectionParameters handshake.ConnectionParametersManager

	streamFramer  *streamFramer
	controlFrames []frames.Frame
}

func newPacketPacker(connectionID protocol.ConnectionID, cryptoSetup handshake.CryptoSetup, connectionParameters handshake.ConnectionParametersManager, streamFramer *streamFramer, perspective protocol.Perspective, version protocol.VersionNumber) *packetPacker {
	return &packetPacker{
		cryptoSetup:           cryptoSetup,
		connectionID:          connectionID,
		connectionParameters:  connectionParameters,
		perspective:           perspective,
		version:               version,
		streamFramer:          streamFramer,
		packetNumberGenerator: newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *frames.ConnectionCloseFrame, leastUnacked protocol.PacketNumber) (*packedPacket, error) {
	// in case the connection is closed, all queued control frames aren't of any use anymore
	// discard them and queue the ConnectionCloseFrame
	p.controlFrames = []frames.Frame{ccf}
	return p.packPacket(nil, leastUnacked, nil)
}

//  RetransmitNonForwardSecurePacket retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPacker) RetransmitNonForwardSecurePacket(stopWaitingFrame *frames.StopWaitingFrame, packet *ackhandler.Packet) (*packedPacket, error) {
	if packet.EncryptionLevel == protocol.EncryptionForwardSecure {
		return nil, errors.New("PacketPacker BUG: forward-secure encrypted handshake packets don't need special treatment")
	}
	if stopWaitingFrame == nil {
		return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a StopWaitingFrame")
	}

	return p.packPacket(stopWaitingFrame, 0, packet)
}

// PackPacket packs a new packet
// the stopWaitingFrame is *guaranteed* to be included in the next packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket(stopWaitingFrame *frames.StopWaitingFrame, controlFrames []frames.Frame, leastUnacked protocol.PacketNumber) (*packedPacket, error) {
	p.controlFrames = append(p.controlFrames, controlFrames...)
	return p.packPacket(stopWaitingFrame, leastUnacked, nil)
}

func (p *packetPacker) packPacket(stopWaitingFrame *frames.StopWaitingFrame, leastUnacked protocol.PacketNumber, handshakePacketToRetransmit *ackhandler.Packet) (*packedPacket, error) {
	// handshakePacketToRetransmit is only set for handshake retransmissions
	isHandshakeRetransmission := (handshakePacketToRetransmit != nil)

	var sealFunc handshake.Sealer
	var encLevel protocol.EncryptionLevel

	if isHandshakeRetransmission {
		var err error
		encLevel = handshakePacketToRetransmit.EncryptionLevel
		sealFunc, err = p.cryptoSetup.GetSealerWithEncryptionLevel(encLevel)
		if err != nil {
			return nil, err
		}
	} else {
		encLevel, sealFunc = p.cryptoSetup.GetSealer()
	}

	currentPacketNumber := p.packetNumberGenerator.Peek()
	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(currentPacketNumber, leastUnacked)
	responsePublicHeader := &PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         currentPacketNumber,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParameters.TruncateConnectionID(),
	}

	if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
		responsePublicHeader.DiversificationNonce = p.cryptoSetup.DiversificationNonce()
	}

	if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
		responsePublicHeader.VersionFlag = true
		responsePublicHeader.VersionNumber = p.version
	}

	publicHeaderLength, err := responsePublicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}

	if stopWaitingFrame != nil {
		stopWaitingFrame.PacketNumber = currentPacketNumber
		stopWaitingFrame.PacketNumberLen = packetNumberLen
	}

	// we're packing a ConnectionClose, don't add any StreamFrames
	var isConnectionClose bool
	if len(p.controlFrames) == 1 {
		_, isConnectionClose = p.controlFrames[0].(*frames.ConnectionCloseFrame)
	}

	var payloadFrames []frames.Frame
	if isHandshakeRetransmission {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		// don't retransmit Acks and StopWaitings
		for _, f := range handshakePacketToRetransmit.Frames {
			switch f.(type) {
			case *frames.AckFrame:
				continue
			case *frames.StopWaitingFrame:
				continue
			}
			payloadFrames = append(payloadFrames, f)
		}
	} else if isConnectionClose {
		payloadFrames = []frames.Frame{p.controlFrames[0]}
	} else {
		maxSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength
		if !p.isForwardSecure {
			maxSize -= protocol.NonForwardSecurePacketSizeReduction
		}
		payloadFrames, err = p.composeNextPacket(stopWaitingFrame, maxSize)
		if err != nil {
			return nil, err
		}
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && stopWaitingFrame != nil {
		return nil, nil
	}

	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)

	if err = responsePublicHeader.Write(buffer, p.version, p.perspective); err != nil {
		return nil, err
	}

	payloadStartIndex := buffer.Len()

	var hasNonCryptoStreamData bool // does this frame contain any stream frame on a stream > 1
	for _, frame := range payloadFrames {
		if sf, ok := frame.(*frames.StreamFrame); ok && sf.StreamID != 1 {
			hasNonCryptoStreamData = true
		}
		err = frame.Write(buffer, p.version)
		if err != nil {
			return nil, err
		}
	}

	if protocol.ByteCount(buffer.Len()+12) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	raw = raw[0:buffer.Len()]
	_ = sealFunc(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], currentPacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+12]

	if hasNonCryptoStreamData && encLevel <= protocol.EncryptionUnencrypted {
		return nil, qerr.AttemptToSendUnencryptedStreamData
	}

	num := p.packetNumberGenerator.Pop()
	if num != currentPacketNumber {
		return nil, errors.New("PacketPacker BUG: Peeked and Popped packet numbers do not match.")
	}

	return &packedPacket{
		number:          currentPacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) composeNextPacket(stopWaitingFrame *frames.StopWaitingFrame, maxFrameSize protocol.ByteCount) ([]frames.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []frames.Frame

	if stopWaitingFrame != nil {
		payloadFrames = append(payloadFrames, stopWaitingFrame)
		minLength, err := stopWaitingFrame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += minLength
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength, _ := frame.MinLength(p.version) // controlFrames does not contain any StopWaitingFrames. So it will *never* return an error
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	// temporarily increase the maxFrameSize by 2 bytes
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus saving 2 bytes and yielding a packet of exactly the correct size
	maxFrameSize += 2

	fs := p.streamFramer.PopStreamFrames(maxFrameSize - payloadLength)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	// TODO: Simplify
	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}

	for b := p.streamFramer.PopBlockedFrame(); b != nil; b = p.streamFramer.PopBlockedFrame() {
		p.controlFrames = append(p.controlFrames, b)
	}

	return payloadFrames, nil
}

func (p *packetPacker) QueueControlFrameForNextPacket(f frames.Frame) {
	p.controlFrames = append(p.controlFrames, f)
}

func (p *packetPacker) SetForwardSecure() {
	p.isForwardSecure = true
}
