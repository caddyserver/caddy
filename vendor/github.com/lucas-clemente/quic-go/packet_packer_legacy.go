package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// sentAndReceivedPacketManager is only needed until STOP_WAITING is removed
type sentAndReceivedPacketManager struct {
	ackhandler.SentPacketHandler
	ackhandler.ReceivedPacketHandler
}

var _ ackFrameSource = &sentAndReceivedPacketManager{}

type packetPackerLegacy struct {
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID

	perspective protocol.Perspective
	version     protocol.VersionNumber
	cryptoSetup sealingManager

	divNonce []byte

	packetNumberGenerator *packetNumberGenerator
	getPacketNumberLen    func(protocol.PacketNumber) protocol.PacketNumberLen
	cryptoStream          cryptoStream
	framer                frameSource
	acks                  ackFrameSource

	omitConnectionID          bool
	maxPacketSize             protocol.ByteCount
	hasSentPacket             bool // has the packetPacker already sent a packet
	numNonRetransmittableAcks int
}

var _ packer = &packetPackerLegacy{}

func newPacketPackerLegacy(
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	getPacketNumberLen func(protocol.PacketNumber) protocol.PacketNumberLen,
	remoteAddr net.Addr, // only used for determining the max packet size
	divNonce []byte,
	cryptoStream cryptoStream,
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) *packetPackerLegacy {
	return &packetPackerLegacy{
		cryptoStream:          cryptoStream,
		cryptoSetup:           cryptoSetup,
		divNonce:              divNonce,
		destConnID:            destConnID,
		srcConnID:             srcConnID,
		perspective:           perspective,
		version:               version,
		framer:                framer,
		acks:                  acks,
		getPacketNumberLen:    getPacketNumberLen,
		packetNumberGenerator: newPacketNumberGenerator(1, protocol.SkipPacketAveragePeriodLength),
		maxPacketSize:         getMaxPacketSize(remoteAddr),
	}
}

// PackConnectionClose packs a packet that ONLY contains a ConnectionCloseFrame
func (p *packetPackerLegacy) PackConnectionClose(ccf *wire.ConnectionCloseFrame) (*packedPacket, error) {
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

func (p *packetPackerLegacy) MaybePackAckPacket() (*packedPacket, error) {
	ack := p.acks.GetAckFrame()
	if ack == nil {
		return nil, nil
	}
	encLevel, sealer := p.cryptoSetup.GetSealer()
	header := p.getHeader(encLevel)
	frames := []wire.Frame{ack}
	// add a STOP_WAITING frame, if necessary
	if p.version.UsesStopWaitingFrames() {
		if swf := p.acks.GetStopWaitingFrame(false); swf != nil {
			swf.PacketNumber = header.PacketNumber
			swf.PacketNumberLen = header.PacketNumberLen
			frames = append(frames, swf)
		}
	}
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
func (p *packetPackerLegacy) PackRetransmission(packet *ackhandler.Packet) ([]*packedPacket, error) {
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
	var swf *wire.StopWaitingFrame
	// add a STOP_WAITING for *every* retransmission
	if p.version.UsesStopWaitingFrames() {
		swf = p.acks.GetStopWaitingFrame(true)
	}
	for len(controlFrames) > 0 || len(streamFrames) > 0 {
		var frames []wire.Frame
		var length protocol.ByteCount

		header := p.getHeader(encLevel)
		headerLength, err := header.GetLength(p.version)
		if err != nil {
			return nil, err
		}
		maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLength

		if p.version.UsesStopWaitingFrames() {
			// create a new STOP_WAIITNG Frame, since we might need to send more than one packet as a retransmission
			stopWaitingFrame := &wire.StopWaitingFrame{
				LeastUnacked:    swf.LeastUnacked,
				PacketNumber:    header.PacketNumber,
				PacketNumberLen: header.PacketNumberLen,
			}
			length += stopWaitingFrame.Length(p.version)
			frames = append(frames, stopWaitingFrame)
		}

		for len(controlFrames) > 0 {
			frame := controlFrames[0]
			frameLen := frame.Length(p.version)
			if length+frameLen > maxSize {
				break
			}
			length += frameLen
			frames = append(frames, frame)
			controlFrames = controlFrames[1:]
		}

		// temporarily increase the maxFrameSize by the (minimum) length of the DataLen field
		// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
		// however, for the last STREAM frame in the packet, we can omit the DataLen, thus yielding a packet of exactly the correct size
		maxSize += 2

		for len(streamFrames) > 0 && length+protocol.MinStreamFrameSize < maxSize {
			frame := streamFrames[0]
			frameToAdd := frame

			sf, err := frame.MaybeSplitOffFrame(maxSize-length, p.version)
			if err != nil {
				return nil, err
			}
			if sf != nil {
				frameToAdd = sf
			} else {
				streamFrames = streamFrames[1:]
			}
			length += frameToAdd.Length(p.version)
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
	return packets, nil
}

// packHandshakeRetransmission retransmits a handshake packet, that was sent with less than forward-secure encryption
func (p *packetPackerLegacy) packHandshakeRetransmission(packet *ackhandler.Packet) (*packedPacket, error) {
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
	if p.version.UsesStopWaitingFrames() { // pack a STOP_WAITING first
		swf := p.acks.GetStopWaitingFrame(true)
		swf.PacketNumber = header.PacketNumber
		swf.PacketNumberLen = header.PacketNumberLen
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
func (p *packetPackerLegacy) PackPacket() (*packedPacket, error) {
	packet, err := p.maybePackCryptoPacket()
	if err != nil {
		return nil, err
	}
	if packet != nil {
		return packet, nil
	}
	// if this is the first packet to be send, make sure it contains stream data
	if !p.hasSentPacket && packet == nil {
		return nil, nil
	}

	encLevel, sealer := p.cryptoSetup.GetSealer()

	header := p.getHeader(encLevel)
	headerLength, err := header.GetLength(p.version)
	if err != nil {
		return nil, err
	}

	maxSize := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - headerLength
	frames, err := p.composeNextPacket(header, maxSize, p.canSendData(encLevel))
	if err != nil {
		return nil, err
	}

	// Check if we have enough frames to send
	if len(frames) == 0 {
		return nil, nil
	}
	// check if this packet only contains an ACK (and maybe a STOP_WAITING)
	if !ackhandler.HasRetransmittableFrames(frames) {
		if p.numNonRetransmittableAcks >= protocol.MaxNonRetransmittableAcks {
			frames = append(frames, &wire.PingFrame{})
			p.numNonRetransmittableAcks = 0
		} else {
			p.numNonRetransmittableAcks++
		}
	} else {
		p.numNonRetransmittableAcks = 0
	}

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

func (p *packetPackerLegacy) maybePackCryptoPacket() (*packedPacket, error) {
	if !p.cryptoStream.hasData() {
		return nil, nil
	}
	encLevel, sealer := p.cryptoSetup.GetSealerForCryptoStream()
	header := p.getHeader(encLevel)
	headerLength, err := header.GetLength(p.version)
	if err != nil {
		return nil, err
	}
	maxLen := p.maxPacketSize - protocol.ByteCount(sealer.Overhead()) - protocol.NonForwardSecurePacketSizeReduction - headerLength
	sf, _ := p.cryptoStream.popStreamFrame(maxLen)
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

func (p *packetPackerLegacy) composeNextPacket(
	header *wire.Header, // only needed to fill in the STOP_WAITING frame
	maxFrameSize protocol.ByteCount,
	canSendStreamFrames bool,
) ([]wire.Frame, error) {
	var length protocol.ByteCount
	var frames []wire.Frame

	// STOP_WAITING and ACK will always fit
	// ACKs need to go first, so that the sentPacketHandler will recognize them
	if ack := p.acks.GetAckFrame(); ack != nil {
		frames = append(frames, ack)
		length += ack.Length(p.version)
		// add a STOP_WAITING, for gQUIC
		if p.version.UsesStopWaitingFrames() {
			if swf := p.acks.GetStopWaitingFrame(false); swf != nil {
				swf.PacketNumber = header.PacketNumber
				swf.PacketNumberLen = header.PacketNumberLen
				frames = append(frames, swf)
				length += swf.Length(p.version)
			}
		}
	}

	var lengthAdded protocol.ByteCount
	frames, lengthAdded = p.framer.AppendControlFrames(frames, maxFrameSize-length)
	length += lengthAdded

	if !canSendStreamFrames {
		return frames, nil
	}

	// temporarily increase the maxFrameSize by the (minimum) length of the DataLen field
	// this leads to a properly sized packet in all cases, since we do all the packet length calculations with StreamFrames that have the DataLen set
	// however, for the last STREAM frame in the packet, we can omit the DataLen, thus yielding a packet of exactly the correct size
	maxFrameSize += 2

	frames = p.framer.AppendStreamFrames(frames, maxFrameSize-length)
	if len(frames) > 0 {
		lastFrame := frames[len(frames)-1]
		if sf, ok := lastFrame.(*wire.StreamFrame); ok {
			sf.DataLenPresent = false
		}
	}
	return frames, nil
}

func (p *packetPackerLegacy) getHeader(encLevel protocol.EncryptionLevel) *wire.Header {
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
		header.PacketNumberLen = protocol.PacketNumberLen4
		if !p.hasSentPacket && p.perspective == protocol.PerspectiveClient {
			header.Type = protocol.PacketTypeInitial
		} else {
			header.Type = protocol.PacketTypeHandshake
		}
	}

	if !p.omitConnectionID || encLevel != protocol.EncryptionForwardSecure {
		header.DestConnectionID = p.destConnID
	}
	if p.perspective == protocol.PerspectiveServer && encLevel == protocol.EncryptionSecure {
		header.Type = protocol.PacketType0RTT
		header.DiversificationNonce = p.divNonce
	}
	if p.perspective == protocol.PerspectiveClient && encLevel != protocol.EncryptionForwardSecure {
		header.VersionFlag = true
	}
	return header
}

func (p *packetPackerLegacy) writeAndSealPacket(
	header *wire.Header,
	frames []wire.Frame,
	sealer handshake.Sealer,
) ([]byte, error) {
	raw := *getPacketBuffer()
	buffer := bytes.NewBuffer(raw[:0])

	if err := header.Write(buffer, p.perspective, p.version); err != nil {
		return nil, err
	}
	payloadStartIndex := buffer.Len()

	for _, frame := range frames {
		if err := frame.Write(buffer, p.version); err != nil {
			return nil, err
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

func (p *packetPackerLegacy) canSendData(encLevel protocol.EncryptionLevel) bool {
	if p.perspective == protocol.PerspectiveClient {
		return encLevel >= protocol.EncryptionSecure
	}
	return encLevel == protocol.EncryptionForwardSecure
}

func (p *packetPackerLegacy) ChangeDestConnectionID(connID protocol.ConnectionID) {
	panic("changing connection IDs not supported by gQUIC")
}

func (p *packetPackerLegacy) HandleTransportParameters(params *handshake.TransportParameters) {
	p.omitConnectionID = params.OmitConnectionID
}
