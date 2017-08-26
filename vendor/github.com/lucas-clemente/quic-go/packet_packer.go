package quic

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
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

	packetNumberGenerator *packetNumberGenerator
	connectionParameters  handshake.ConnectionParametersManager
	streamFramer          *streamFramer

	controlFrames []frames.Frame
	stopWaiting   *frames.StopWaitingFrame
	ackFrame      *frames.AckFrame
	leastUnacked  protocol.PacketNumber
}

func newPacketPacker(connectionID protocol.ConnectionID,
	cryptoSetup handshake.CryptoSetup,
	connectionParameters handshake.ConnectionParametersManager,
	streamFramer *streamFramer,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
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
func (p *packetPacker) PackConnectionClose(ccf *frames.ConnectionCloseFrame) (*packedPacket, error) {
	frames := []frames.Frame{ccf}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	ph := p.getPublicHeader(encLevel)
	raw, err := p.writeAndSealPacket(ph, frames, sealer)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, err
}

func (p *packetPacker) PackAckPacket() (*packedPacket, error) {
	if p.ackFrame == nil {
		return nil, errors.New("packet packer BUG: no ack frame queued")
	}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	ph := p.getPublicHeader(encLevel)
	frames := []frames.Frame{p.ackFrame}
	if p.stopWaiting != nil {
		p.stopWaiting.PacketNumber = ph.PacketNumber
		p.stopWaiting.PacketNumberLen = ph.PacketNumberLen
		frames = append(frames, p.stopWaiting)
		p.stopWaiting = nil
	}
	p.ackFrame = nil
	raw, err := p.writeAndSealPacket(ph, frames, sealer)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, err
}

// PackHandshakeRetransmission retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPacker) PackHandshakeRetransmission(packet *ackhandler.Packet) (*packedPacket, error) {
	if packet.EncryptionLevel == protocol.EncryptionForwardSecure {
		return nil, errors.New("PacketPacker BUG: forward-secure encrypted handshake packets don't need special treatment")
	}
	sealer, err := p.cryptoSetup.GetSealerWithEncryptionLevel(packet.EncryptionLevel)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting == nil {
		return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a StopWaitingFrame")
	}
	ph := p.getPublicHeader(packet.EncryptionLevel)
	p.stopWaiting.PacketNumber = ph.PacketNumber
	p.stopWaiting.PacketNumberLen = ph.PacketNumberLen
	frames := append([]frames.Frame{p.stopWaiting}, packet.Frames...)
	p.stopWaiting = nil
	raw, err := p.writeAndSealPacket(ph, frames, sealer)
	return &packedPacket{
		number:          ph.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: packet.EncryptionLevel,
	}, err
}

// PackPacket packs a new packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket() (*packedPacket, error) {
	if p.streamFramer.HasCryptoStreamFrame() {
		return p.packCryptoPacket()
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	publicHeader := p.getPublicHeader(encLevel)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting != nil {
		p.stopWaiting.PacketNumber = publicHeader.PacketNumber
		p.stopWaiting.PacketNumberLen = publicHeader.PacketNumberLen
	}

	maxSize := protocol.MaxFrameAndPublicHeaderSize - publicHeaderLength
	payloadFrames, err := p.composeNextPacket(maxSize, p.canSendData(encLevel))
	if err != nil {
		return nil, err
	}

	// Check if we have enough frames to send
	if len(payloadFrames) == 0 {
		return nil, nil
	}
	// Don't send out packets that only contain a StopWaitingFrame
	if len(payloadFrames) == 1 && p.stopWaiting != nil {
		return nil, nil
	}
	p.stopWaiting = nil
	p.ackFrame = nil

	raw, err := p.writeAndSealPacket(publicHeader, payloadFrames, sealer)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) packCryptoPacket() (*packedPacket, error) {
	encLevel, sealer := p.cryptoSetup.GetSealerForCryptoStream()
	publicHeader := p.getPublicHeader(encLevel)
	publicHeaderLength, err := publicHeader.GetLength(p.perspective)
	if err != nil {
		return nil, err
	}
	maxLen := protocol.MaxFrameAndPublicHeaderSize - protocol.NonForwardSecurePacketSizeReduction - publicHeaderLength
	frames := []frames.Frame{p.streamFramer.PopCryptoStreamFrame(maxLen)}
	raw, err := p.writeAndSealPacket(publicHeader, frames, sealer)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		number:          publicHeader.PacketNumber,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) composeNextPacket(
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
) ([]frames.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []frames.Frame

	// STOP_WAITING and ACK will always fit
	if p.stopWaiting != nil {
		payloadFrames = append(payloadFrames, p.stopWaiting)
		l, err := p.stopWaiting.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}
	if p.ackFrame != nil {
		payloadFrames = append(payloadFrames, p.ackFrame)
		l, err := p.ackFrame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
		payloadLength += l
	}

	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength, err := frame.MinLength(p.version)
		if err != nil {
			return nil, err
		}
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

	if !canSendStreamFrames {
		return payloadFrames, nil
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

func (p *packetPacker) QueueControlFrame(frame frames.Frame) {
	switch f := frame.(type) {
	case *frames.StopWaitingFrame:
		p.stopWaiting = f
	case *frames.AckFrame:
		p.ackFrame = f
	default:
		p.controlFrames = append(p.controlFrames, f)
	}
}

func (p *packetPacker) getPublicHeader(encLevel protocol.EncryptionLevel) *PublicHeader {
	pnum := p.packetNumberGenerator.Peek()
	packetNumberLen := protocol.GetPacketNumberLengthForPublicHeader(pnum, p.leastUnacked)
	publicHeader := &PublicHeader{
		ConnectionID:         p.connectionID,
		PacketNumber:         pnum,
		PacketNumberLen:      packetNumberLen,
		TruncateConnectionID: p.connectionParameters.TruncateConnectionID(),
	}

	if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
		publicHeader.DiversificationNonce = p.cryptoSetup.DiversificationNonce()
	}
	if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
		publicHeader.VersionFlag = true
		publicHeader.VersionNumber = p.version
	}

	return publicHeader
}

func (p *packetPacker) writeAndSealPacket(
	publicHeader *PublicHeader,
	payloadFrames []frames.Frame,
	sealer handshake.Sealer,
) ([]byte, error) {
	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)

	if err := publicHeader.Write(buffer, p.version, p.perspective); err != nil {
		return nil, err
	}
	payloadStartIndex := buffer.Len()
	for _, frame := range payloadFrames {
		err := frame.Write(buffer, p.version)
		if err != nil {
			return nil, err
		}
	}
	if protocol.ByteCount(buffer.Len()+12) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	raw = raw[0:buffer.Len()]
	_ = sealer(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], publicHeader.PacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+12]

	num := p.packetNumberGenerator.Pop()
	if num != publicHeader.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}

	return raw, nil
}

func (p *packetPacker) canSendData(encLevel protocol.EncryptionLevel) bool {
	if p.perspective == protocol.PerspectiveClient {
		return encLevel >= protocol.EncryptionSecure
	}
	return encLevel == protocol.EncryptionForwardSecure
}

func (p *packetPacker) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.leastUnacked = leastUnacked
}
