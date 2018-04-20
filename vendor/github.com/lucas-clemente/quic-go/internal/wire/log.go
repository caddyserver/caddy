package wire

import "github.com/lucas-clemente/quic-go/internal/utils"

// LogFrame logs a frame, either sent or received
func LogFrame(logger utils.Logger, frame Frame, sent bool) {
	if !logger.Debug() {
		return
	}
	dir := "<-"
	if sent {
		dir = "->"
	}
	switch f := frame.(type) {
	case *StreamFrame:
		logger.Debugf("\t%s &wire.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", dir, f.StreamID, f.FinBit, f.Offset, f.DataLen(), f.Offset+f.DataLen())
	case *StopWaitingFrame:
		if sent {
			logger.Debugf("\t%s &wire.StopWaitingFrame{LeastUnacked: 0x%x, PacketNumberLen: 0x%x}", dir, f.LeastUnacked, f.PacketNumberLen)
		} else {
			logger.Debugf("\t%s &wire.StopWaitingFrame{LeastUnacked: 0x%x}", dir, f.LeastUnacked)
		}
	case *AckFrame:
		logger.Debugf("\t%s &wire.AckFrame{LargestAcked: 0x%x, LowestAcked: 0x%x, AckRanges: %#v, DelayTime: %s}", dir, f.LargestAcked, f.LowestAcked, f.AckRanges, f.DelayTime.String())
	default:
		logger.Debugf("\t%s %#v", dir, frame)
	}
}
