package frames

import "github.com/lucas-clemente/quic-go/utils"

// LogFrame logs a frame, either sent or received
func LogFrame(frame Frame, sent bool) {
	if !utils.Debug() {
		return
	}
	dir := "<-"
	if sent {
		dir = "->"
	}
	switch f := frame.(type) {
	case *StreamFrame:
		utils.Debugf("\t%s &frames.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", dir, f.StreamID, f.FinBit, f.Offset, f.DataLen(), f.Offset+f.DataLen())
	case *StopWaitingFrame:
		if sent {
			utils.Debugf("\t%s &frames.StopWaitingFrame{LeastUnacked: 0x%x, PacketNumberLen: 0x%x}", dir, f.LeastUnacked, f.PacketNumberLen)
		} else {
			utils.Debugf("\t%s &frames.StopWaitingFrame{LeastUnacked: 0x%x}", dir, f.LeastUnacked)
		}
	case *AckFrame:
		utils.Debugf("\t%s &frames.AckFrame{LargestAcked: 0x%x, LowestAcked: 0x%x, AckRanges: %#v, DelayTime: %s}", dir, f.LargestAcked, f.LowestAcked, f.AckRanges, f.DelayTime.String())
	default:
		utils.Debugf("\t%s %#v", dir, frame)
	}
}
