package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type packedPacket struct {
	header          *wire.Header
	raw             []byte
	frames          []wire.Frame
	encryptionLevel protocol.EncryptionLevel
}

func (p *packedPacket) ToAckHandlerPacket() *ackhandler.Packet {
	return &ackhandler.Packet{
		PacketNumber:    p.header.PacketNumber,
		PacketType:      p.header.Type,
		Frames:          p.frames,
		Length:          protocol.ByteCount(len(p.raw)),
		EncryptionLevel: p.encryptionLevel,
		SendTime:        time.Now(),
	}
}

type sealingManager interface {
	GetSealer() (protocol.EncryptionLevel, handshake.Sealer)
	GetSealerForCryptoStream() (protocol.EncryptionLevel, handshake.Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (handshake.Sealer, error)
}

type streamFrameSource interface {
	HasCryptoStreamData() bool
	PopCryptoStreamFrame(protocol.ByteCount) *wire.StreamFrame
	PopStreamFrames(protocol.ByteCount) []*wire.StreamFrame
}

type packetPacker struct {
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID

	perspective protocol.Perspective
	version     protocol.VersionNumber
	cryptoSetup sealingManager

	token    []byte
	divNonce []byte

	packetNumberGenerator *packetNumberGenerator
	getPacketNumberLen    func(protocol.PacketNumber) protocol.PacketNumberLen
	streams               streamFrameSource

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame

	stopWaiting               *wire.StopWaitingFrame
	ackFrame                  *wire.AckFrame
	omitConnectionID          bool
	maxPacketSize             protocol.ByteCount
	hasSentPacket             bool // has the packetPacker already sent a packet
	numNonRetransmittableAcks int
}

func newPacketPacker(
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	initialPacketNumber protocol.PacketNumber,
	getPacketNumberLen func(protocol.PacketNumber) protocol.PacketNumberLen,
	remoteAddr net.Addr, // only used for determining the max packet size
	token []byte,
	divNonce []byte,
	cryptoSetup sealingManager,
	streamFramer streamFrameSource,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPacker {
	maxPacketSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	// If this is not a UDP address, we don't know anything about the MTU.
	// Use the minimum size of an Initial packet as the max packet size.
	if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		// If ip is not an IPv4 address, To4 returns nil.
		// Note that there might be some corner cases, where this is not correct.
		// See https://stackoverflow.com/questions/22751035/golang-distinguish-ipv4-ipv6.
		if udpAddr.IP.To4() == nil {
			maxPacketSize = protocol.MaxPacketSizeIPv6
		} else {
			maxPacketSize = protocol.MaxPacketSizeIPv4
		}
	}
	return &packetPacker{
		cryptoSetup:           cryptoSetup,
		divNonce:              divNonce,
		token:                 token,
		destConnID:            destConnID,
		srcConnID:             srcConnID,
		perspective:           perspective,
		version:               version,
		streams:               streamFramer,
		getPacketNumberLen:    getPacketNumberLen,
		packetNumberGenerator: newPacketNumberGenerator(initialPacketNumber, protocol.SkipPacketAveragePeriodLength),
		maxPacketSize:         maxPacketSize,
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

// PackRetransmission packs a retransmission
// For packets sent after completion of the handshake, it might happen that 2 packets have to be sent.
// This can happen e.g. when a longer packet number is used in the header.
func (p *packetPacker) PackRetransmission(packet *ackhandler.Packet) ([]*packedPacket, error) {
	if packet.EncryptionLevel != protocol.EncryptionForwardSecure {
		p, err := p.packHandshakeRetransmission(packet)
		return []*packedPacket{p}, err
	}

	var controlFrames []wire.Frame
	var streamFrames []*wire.StreamFrame
	for _, f := range packet.Frames {
		if sf, ok := f.(*wire.StreamFrame); ok {
			sf.DataLenPresent = true
			streamFrames = append(streamFrames, sf)
		} else {
			controlFrames = append(controlFrames, f)
		}
	}

	var packets []*packedPacket
	encLevel, sealer := p.cryptoSetup.GetSealer()
	for len(controlFrames) > 0 || len(streamFrames) > 0 {
		var frames []wire.Frame
		var payloadLength protocol.ByteCount

		header := p.getHeader(encLevel)
		headerLength, err := header.GetLength(p.version)
		if err != nil {
			return nil, err
		}
		maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLength

		// for gQUIC: add a STOP_WAITING for *every* retransmission
		if p.version.UsesStopWaitingFrames() {
			if p.stopWaiting == nil {
				return nil, errors.New("PacketPacker BUG: Handshake retransmissions must contain a STOP_WAITING frame")
			}
			// create a new StopWaitingFrame, since we might need to send more than one packet as a retransmission
			swf := &wire.StopWaitingFrame{
				LeastUnacked:    p.stopWaiting.LeastUnacked,
				PacketNumber:    header.PacketNumber,
				PacketNumberLen: header.PacketNumberLen,
			}
			payloadLength += swf.Length(p.version)
			frames = append(frames, swf)
		}

		for len(controlFrames) > 0 {
			frame := controlFrames[0]
			length := frame.Length(p.version)
			if payloadLength+length > maxSize {
				break
			}
			payloadLength += length
			frames = append(frames, frame)
			controlFrames = controlFrames[1:]
		}

		// temporarily increase the maxFrameSize by the (minimum) length of the DataLen field
		// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
		// however, for the last STREAM frame in the packet, we can omit the DataLen, thus yielding a packet of exactly the correct size
		// for gQUIC STREAM frames, DataLen is always 2 bytes
		// for IETF draft style STREAM frames, the length is encoded to either 1 or 2 bytes
		if p.version.UsesIETFFrameFormat() {
			maxSize++
		} else {
			maxSize += 2
		}
		for len(streamFrames) > 0 && payloadLength+protocol.MinStreamFrameSize < maxSize {
			// TODO: optimize by setting DataLenPresent = false on all but the last STREAM frame
			frame := streamFrames[0]
			frameToAdd := frame

			sf, err := frame.MaybeSplitOffFrame(maxSize-payloadLength, p.version)
			if err != nil {
				return nil, err
			}
			if sf != nil {
				frameToAdd = sf
			} else {
				streamFrames = streamFrames[1:]
			}
			payloadLength += frameToAdd.Length(p.version)
			frames = append(frames, frameToAdd)
		}
		if sf, ok := frames[len(frames)-1].(*wire.StreamFrame); ok {
			sf.DataLenPresent = false
		}
		raw, err := p.writeAndSealPacket(header, frames, sealer)
		if err != nil {
			return nil, err
		}
		packets = append(packets, &packedPacket{
			header:          header,
			raw:             raw,
			frames:          frames,
			encryptionLevel: encLevel,
		})
	}
	p.stopWaiting = nil
	return packets, nil
}

// packHandshakeRetransmission retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPacker) packHandshakeRetransmission(packet *ackhandler.Packet) (*packedPacket, error) {
	sealer, err := p.cryptoSetup.GetSealerWithEncryptionLevel(packet.EncryptionLevel)
	if err != nil {
		return nil, err
	}
	// make sure that the retransmission for an Initial packet is sent as an Initial packet
	if packet.PacketType == protocol.PacketTypeInitial {
		p.hasSentPacket = false
	}
	header := p.getHeader(packet.EncryptionLevel)
	header.Type = packet.PacketType
	var frames []wire.Frame
	if p.version.UsesStopWaitingFrames() { // for gQUIC: pack a STOP_WAITING first
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
	headerLength, err := header.GetLength(p.version)
	if err != nil {
		return nil, err
	}
	if p.stopWaiting != nil {
		p.stopWaiting.PacketNumber = header.PacketNumber
		p.stopWaiting.PacketNumberLen = header.PacketNumberLen
	}

	maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLength
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
	headerLength, err := header.GetLength(p.version)
	if err != nil {
		return nil, err
	}
	maxLen := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - protocol.NonForwardSecurePacketSizeReduction - headerLength
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
		l := p.ackFrame.Length(p.version)
		payloadLength += l
	}
	if p.stopWaiting != nil { // a STOP_WAITING will only be queued when using gQUIC
		payloadFrames = append(payloadFrames, p.stopWaiting)
		payloadLength += p.stopWaiting.Length(p.version)
	}

	p.controlFrameMutex.Lock()
	for len(p.controlFrames) > 0 {
		frame := p.controlFrames[len(p.controlFrames)-1]
		length := frame.Length(p.version)
		if payloadLength+length > maxFrameSize {
			break
		}
		payloadFrames = append(payloadFrames, frame)
		payloadLength += length
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
	// however, for the last STREAM frame in the packet, we can omit the DataLen, thus yielding a packet of exactly the correct size
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
	packetNumberLen := p.getPacketNumberLen(pnum)

	header := &wire.Header{
		PacketNumber:    pnum,
		PacketNumberLen: packetNumberLen,
		Version:         p.version,
	}

	if p.version.UsesIETFHeaderFormat() && encLevel != protocol.EncryptionForwardSecure {
		header.IsLongHeader = true
		header.SrcConnectionID = p.srcConnID
		if !p.version.UsesVarintPacketNumbers() {
			header.PacketNumberLen = protocol.PacketNumberLen4
		}
		// Set the payload len to maximum size.
		// Since it is encoded as a varint, this guarantees us that the header will end up at most as big as GetLength() returns.
		header.PayloadLen = p.maxPacketSize
		if !p.hasSentPacket && p.perspective == protocol.PerspectiveClient {
			header.Type = protocol.PacketTypeInitial
			header.Token = p.token
		} else {
			header.Type = protocol.PacketTypeHandshake
		}
	}

	if !p.omitConnectionID || encLevel != protocol.EncryptionForwardSecure {
		header.DestConnectionID = p.destConnID
	}
	if !p.version.UsesTLS() {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
			header.Type = protocol.PacketType0RTT
			header.DiversificationNonce = p.divNonce
		}
		if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
			header.VersionFlag = true
		}
	}
	return header
}

func (p *packetPacker) writeAndSealPacket(
	header *wire.Header,
	payloadFrames []wire.Frame,
	sealer handshake.Sealer,
) ([]byte, error) {
	raw := *getPacketBuffer()
	buffer := bytes.NewBuffer(raw[:0])

	// the payload length is only needed for Long Headers
	if header.IsLongHeader {
		if header.Type == protocol.PacketTypeInitial {
			headerLen, _ := header.GetLength(p.version)
			header.PayloadLen = protocol.ByteCount(protocol.MinInitialPacketSize) - headerLen
		} else {
			payloadLen := protocol.ByteCount(sealer.Overhead())
			for _, frame := range payloadFrames {
				payloadLen += frame.Length(p.version)
			}
			header.PayloadLen = payloadLen
		}
	}

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

	if size := protocol.ByteCount(buffer.Len() + sealer.Overhead()); size > p.maxPacketSize {
		return nil, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, p.maxPacketSize)
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

func (p *packetPacker) SetOmitConnectionID() {
	p.omitConnectionID = true
}

func (p *packetPacker) ChangeDestConnectionID(connID protocol.ConnectionID) {
	p.destConnID = connID
}

func (p *packetPacker) SetMaxPacketSize(size protocol.ByteCount) {
	p.maxPacketSize = utils.MinByteCount(p.maxPacketSize, size)
}
