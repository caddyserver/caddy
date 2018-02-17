package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFrameSorter struct {
	queuedFrames map[protocol.ByteCount]*wire.StreamFrame
	readPosition protocol.ByteCount
	gaps         *utils.ByteIntervalList
}

var (
	errTooManyGapsInReceivedStreamData = errors.New("Too many gaps in received StreamFrame data")
	errDuplicateStreamData             = errors.New("Duplicate Stream Data")
	errEmptyStreamData                 = errors.New("Stream Data empty")
)

func newStreamFrameSorter() *streamFrameSorter {
	s := streamFrameSorter{
		gaps:         utils.NewByteIntervalList(),
		queuedFrames: make(map[protocol.ByteCount]*wire.StreamFrame),
	}
	s.gaps.PushFront(utils.ByteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *streamFrameSorter) Push(frame *wire.StreamFrame) error {
	if frame.DataLen() == 0 {
		if frame.FinBit {
			s.queuedFrames[frame.Offset] = frame
			return nil
		}
		return errEmptyStreamData
	}

	var wasCut bool
	if oldFrame, ok := s.queuedFrames[frame.Offset]; ok {
		if frame.DataLen() <= oldFrame.DataLen() {
			return errDuplicateStreamData
		}
		frame.Data = frame.Data[oldFrame.DataLen():]
		frame.Offset += oldFrame.DataLen()
		wasCut = true
	}

	start := frame.Offset
	end := frame.Offset + frame.DataLen()

	// skip all gaps that are before this stream frame
	var gap *utils.ByteIntervalElement
	for gap = s.gaps.Front(); gap != nil; gap = gap.Next() {
		// the frame is a duplicate. Ignore it
		if end <= gap.Value.Start {
			return errDuplicateStreamData
		}
		if end > gap.Value.Start && start <= gap.Value.End {
			break
		}
	}

	if gap == nil {
		return errors.New("StreamFrameSorter BUG: no gap found")
	}

	if start < gap.Value.Start {
		add := gap.Value.Start - start
		frame.Offset += add
		start += add
		frame.Data = frame.Data[add:]
		wasCut = true
	}

	// find the highest gaps whose Start lies before the end of the frame
	endGap := gap
	for end >= endGap.Value.End {
		nextEndGap := endGap.Next()
		if nextEndGap == nil {
			return errors.New("StreamFrameSorter BUG: no end gap found")
		}
		if endGap != gap {
			s.gaps.Remove(endGap)
		}
		if end <= nextEndGap.Value.Start {
			break
		}
		// delete queued frames completely covered by the current frame
		delete(s.queuedFrames, endGap.Value.End)
		endGap = nextEndGap
	}

	if end > endGap.Value.End {
		cutLen := end - endGap.Value.End
		len := frame.DataLen() - cutLen
		end -= cutLen
		frame.Data = frame.Data[:len]
		wasCut = true
	}

	if start == gap.Value.Start {
		if end >= gap.Value.End {
			// the frame completely fills this gap
			// delete the gap
			s.gaps.Remove(gap)
		}
		if end < endGap.Value.End {
			// the frame covers the beginning of the gap
			// adjust the Start value to shrink the gap
			endGap.Value.Start = end
		}
	} else if end == endGap.Value.End {
		// the frame covers the end of the gap
		// adjust the End value to shrink the gap
		gap.Value.End = start
	} else {
		if gap == endGap {
			// the frame lies within the current gap, splitting it into two
			// insert a new gap and adjust the current one
			intv := utils.ByteInterval{Start: end, End: gap.Value.End}
			s.gaps.InsertAfter(intv, gap)
			gap.Value.End = start
		} else {
			gap.Value.End = start
			endGap.Value.Start = end
		}
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errTooManyGapsInReceivedStreamData
	}

	if wasCut {
		data := make([]byte, frame.DataLen())
		copy(data, frame.Data)
		frame.Data = data
	}

	s.queuedFrames[frame.Offset] = frame
	return nil
}

func (s *streamFrameSorter) Pop() *wire.StreamFrame {
	frame := s.Head()
	if frame != nil {
		s.readPosition += frame.DataLen()
		delete(s.queuedFrames, frame.Offset)
	}
	return frame
}

func (s *streamFrameSorter) Head() *wire.StreamFrame {
	frame, ok := s.queuedFrames[s.readPosition]
	if ok {
		return frame
	}
	return nil
}
