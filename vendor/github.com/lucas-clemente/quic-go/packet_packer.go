package quic

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packedPacket struct {
	header          *wire.Header
	raw             []byte
	frames          []wire.Frame
	encryptionLevel protocol.EncryptionLevel
}

type streamFrameSource interface {
	HasCryptoStreamData() bool
	PopCryptoStreamFrame(protocol.ByteCount) *wire.StreamFrame
	PopStreamFrames(protocol.ByteCount) []*wire.StreamFrame
}

type packetPacker struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	cryptoSetup  handshake.CryptoSetup

	packetNumberGenerator *packetNumberGenerator
	streams               streamFrameSource

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame

	stopWaiting               *wire.StopWaitingFrame
	ackFrame                  *wire.AckFrame
	leastUnacked              protocol.PacketNumber
	omitConnectionID          bool
	hasSentPacket             bool // has the packetPacker already sent a packet
	numNonRetransmittableAcks int
}

func newPacketPacker(connectionID protocol.ConnectionID,
	initialPacketNumber protocol.PacketNumber,
	cryptoSetup handshake.CryptoSetup,
	streamFramer streamFrameSource,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	return &packetPacker{
		cryptoSetup:           cryptoSetup,
		connectionID:          connectionID,
		perspective:           perspective,
		version:               version,
		streams:               streamFramer,
		packetNumberGenerator: newPacketNumberGenerator(initialPacketNumber, protocol.SkipPacketAveragePeriodLength),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPacker) PackConnectionClose(ccf *wire.ConnectionCloseFrame) (*packedPacket, error) {
	frames := []wire.Frame{ccf}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	header := p.getHeader(encLevel)
	raw, err := p.writeAndSealPacket(header, frames, sealer)
	return &packedPacket{
		header:          header,
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
	header := p.getHeader(encLevel)
	frames := []wire.Frame{p.ackFrame}
	if p.stopWaiting != nil { // a STOP_WAITING will only be queued when using gQUIC
		p.stopWaiting.PacketNumber = header.PacketNumber
		p.stopWaiting.PacketNumberLen = header.PacketNumberLen
		frames = append(frames, p.stopWaiting)
		p.stopWaiting = nil
	}
	p.ackFrame = nil
	raw, err := p.writeAndSealPacket(header, frames, sealer)
	return &packedPacket{
		header:          header,
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
	header := p.getHeader(packet.EncryptionLevel)
	var frames []wire.Frame
	if !p.version.UsesIETFFrameFormat() { // for gQUIC: pack a STOP_WAITING first
		if p.stopWaiting == nil {
			return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a STOP_WAITING frame")
		}
		swf := p.stopWaiting
		swf.PacketNumber = header.PacketNumber
		swf.PacketNumberLen = header.PacketNumberLen
		p.stopWaiting = nil
		frames = append([]wire.Frame{swf}, packet.Frames...)
	} else {
		frames = packet.Frames
	}
	raw, err := p.writeAndSealPacket(header, frames, sealer)
	return &packedPacket{
		header:          header,
		raw:             raw,
		frames:          frames,
		encryptionLevel: packet.EncryptionLevel,
	}, err
}

// PackPacket packs a new packet
// the other controlFrames are sent in the next packet, but might be queued and sent in the next packet if the packet would overflow MaxPacketSize otherwise
func (p *packetPacker) PackPacket() (*packedPacket, error) {
	hasCryptoStreamFrame := p.streams.HasCryptoStreamData()
	// if this is the first packet to be send, make sure it contains stream data
	if !p.hasSentPacket && !hasCryptoStreamFrame {
		return nil, nil
	}
	if hasCryptoStreamFrame {
		return p.packCryptoPacket()
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	header := p.getHeader(encLevel)
	headerLength, err := header.GetLength(p.perspective, p.version)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting != nil {
		p.stopWaiting.PacketNumber = header.PacketNumber
		p.stopWaiting.PacketNumberLen = header.PacketNumberLen
	}

	maxSize := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLength
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
	if p.ackFrame != nil {
		// check if this packet only contains an ACK (and maybe a STOP_WAITING)
		if len(payloadFrames) == 1 || (p.stopWaiting != nil && len(payloadFrames) == 2) {
			if p.numNonRetransmittableAcks >= protocol.MaxNonRetransmittableAcks {
				payloadFrames = append(payloadFrames, &wire.PingFrame{})
				p.numNonRetransmittableAcks = 0
			} else {
				p.numNonRetransmittableAcks++
			}
		} else {
			p.numNonRetransmittableAcks = 0
		}
	}
	p.stopWaiting = nil
	p.ackFrame = nil

	raw, err := p.writeAndSealPacket(header, payloadFrames, sealer)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		header:          header,
		raw:             raw,
		frames:          payloadFrames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) packCryptoPacket() (*packedPacket, error) {
	encLevel, sealer := p.cryptoSetup.GetSealerForCryptoStream()
	header := p.getHeader(encLevel)
	headerLength, err := header.GetLength(p.perspective, p.version)
	if err != nil {
		return nil, err
	}
	maxLen := protocol.MaxPacketSize - protocol.ByteCount(sealer.Overhead()) - protocol.NonForwardSecurePacketSizeReduction - headerLength
	sf := p.streams.PopCryptoStreamFrame(maxLen)
	sf.DataLenPresent = false
	frames := []wire.Frame{sf}
	raw, err := p.writeAndSealPacket(header, frames, sealer)
	if err != nil {
		return nil, err
	}
	return &packedPacket{
		header:          header,
		raw:             raw,
		frames:          frames,
		encryptionLevel: encLevel,
	}, nil
}

func (p *packetPacker) composeNextPacket(
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
) ([]wire.Frame, error) {
	var payloadLength protocol.ByteCount
	var payloadFrames []wire.Frame

	// STOP_WAITING and ACK will always fit
	if p.ackFrame != nil { // ACKs need to go first, so that the sentPacketHandler will recognize them
		payloadFrames = append(payloadFrames, p.ackFrame)
		l := p.ackFrame.MinLength(p.version)
		payloadLength += l
	}
	if p.stopWaiting != nil { // a STOP_WAITING will only be queued when using gQUIC
		payloadFrames = append(payloadFrames, p.stopWaiting)
		payloadLength += p.stopWaiting.MinLength(p.version)
	}

	p.controlFrameMutex.Lock()
	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		minLength := frame.MinLength(p.version)
		if payloadLength+minLength > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += minLength
		p.controlFrames = p.controlFrames[:len(p.controlFrames)-1]
	}
	p.controlFrameMutex.Unlock()

	if payloadLength > maxFrameSize {
		return nil, fmt.Errorf("Packet Packer BUG: packet payload (%d) too large (%d)", payloadLength, maxFrameSize)
	}

	if !canSendStreamFrames {
		return payloadFrames, nil
	}

	// temporarily increase the maxFrameSize by the (minimum) length of the DataLen field
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last StreamFrame in the packet, we can omit the DataLen, thus yielding a packet of exactly the correct size
	// for gQUIC STREAM frames, DataLen is always 2 bytes
	// for IETF draft style STREAM frames, the length is encoded to either 1 or 2 bytes
	if p.version.UsesIETFFrameFormat() {
		maxFrameSize++
	} else {
		maxFrameSize += 2
	}

	fs := p.streams.PopStreamFrames(maxFrameSize - payloadLength)
	if len(fs) != 0 {
		fs[len(fs)-1].DataLenPresent = false
	}

	for _, f := range fs {
		payloadFrames = append(payloadFrames, f)
	}
	return payloadFrames, nil
}

func (p *packetPacker) QueueControlFrame(frame wire.Frame) {
	switch f := frame.(type) {
	case *wire.StopWaitingFrame:
		p.stopWaiting = f
	case *wire.AckFrame:
		p.ackFrame = f
	default:
		p.controlFrameMutex.Lock()
		p.controlFrames = append(p.controlFrames, f)
		p.controlFrameMutex.Unlock()
	}
}

func (p *packetPacker) getHeader(encLevel protocol.EncryptionLevel) *wire.Header {
	pnum := p.packetNumberGenerator.Peek()
	packetNumberLen := protocol.GetPacketNumberLengthForHeader(pnum, p.leastUnacked)

	header := &wire.Header{
		ConnectionID:    p.connectionID,
		PacketNumber:    pnum,
		PacketNumberLen: packetNumberLen,
	}

	if p.version.UsesTLS() && encLevel != protocol.EncryptionForwardSecure {
		header.PacketNumberLen = protocol.PacketNumberLen4
		header.IsLongHeader = true
		if !p.hasSentPacket && p.perspective == protocol.PerspectiveClient {
			header.Type = protocol.PacketTypeInitial
		} else {
			header.Type = protocol.PacketTypeHandshake
		}
	}

	if p.omitConnectionID && encLevel == protocol.EncryptionForwardSecure {
		header.OmitConnectionID = true
	}
	if !p.version.UsesTLS() {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
			header.DiversificationNonce = p.cryptoSetup.DiversificationNonce()
		}
		if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
			header.VersionFlag = true
			header.Version = p.version
		}
	} else {
		if encLevel != protocol.EncryptionForwardSecure {
			header.Version = p.version
		}
	}
	return header
}

func (p *packetPacker) writeAndSealPacket(
	header *wire.Header,
	payloadFrames []wire.Frame,
	sealer handshake.Sealer,
) ([]byte, error) {
	raw := getPacketBuffer()
	buffer := bytes.NewBuffer(raw)

	if err := header.Write(buffer, p.perspective, p.version); err != nil {
		return nil, err
	}
	payloadStartIndex := buffer.Len()

	// the Initial packet needs to be padded, so the last STREAM frame must have the data length present
	if header.Type == protocol.PacketTypeInitial {
		lastFrame := payloadFrames[len(payloadFrames)-1]
		if sf, ok := lastFrame.(*wire.StreamFrame); ok {
			sf.DataLenPresent = true
		}
	}
	for _, frame := range payloadFrames {
		if err := frame.Write(buffer, p.version); err != nil {
			return nil, err
		}
	}
	// if this is an IETF QUIC Initial packet, we need to pad it to fulfill the minimum size requirement
	// in gQUIC, padding is handled in the CHLO
	if header.Type == protocol.PacketTypeInitial {
		paddingLen := protocol.MinInitialPacketSize - sealer.Overhead() - buffer.Len()
		if paddingLen > 0 {
			buffer.Write(bytes.Repeat([]byte{0}, paddingLen))
		}
	}
	if protocol.ByteCount(buffer.Len()+sealer.Overhead()) > protocol.MaxPacketSize {
		return nil, errors.New("PacketPacker BUG: packet too large")
	}

	raw = raw[0:buffer.Len()]
	_ = sealer.Seal(raw[payloadStartIndex:payloadStartIndex], raw[payloadStartIndex:], header.PacketNumber, raw[:payloadStartIndex])
	raw = raw[0 : buffer.Len()+sealer.Overhead()]

	num := p.packetNumberGenerator.Pop()
	if num != header.PacketNumber {
		return nil, errors.New("packetPacker BUG: Peeked and Popped packet numbers do not match")
	}
	p.hasSentPacket = true
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

func (p *packetPacker) SetOmitConnectionID() {
	p.omitConnectionID = true
}
