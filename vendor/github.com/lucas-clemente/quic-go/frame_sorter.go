package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type frameSorter struct {
	queue       map[protocol.ByteCount][]byte
	readPos     protocol.ByteCount
	finalOffset protocol.ByteCount
	gaps        *utils.ByteIntervalList
}

var errDuplicateStreamData = errors.New("Duplicate Stream Data")

func newFrameSorter() *frameSorter {
	s := frameSorter{
		gaps:        utils.NewByteIntervalList(),
		queue:       make(map[protocol.ByteCount][]byte),
		finalOffset: protocol.MaxByteCount,
	}
	s.gaps.PushFront(utils.ByteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *frameSorter) Push(data []byte, offset protocol.ByteCount, fin bool) error {
	err := s.push(data, offset, fin)
	if err == errDuplicateStreamData {
		return nil
	}
	return err
}

func (s *frameSorter) push(data []byte, offset protocol.ByteCount, fin bool) error {
	if fin {
		s.finalOffset = offset + protocol.ByteCount(len(data))
	}
	if len(data) == 0 {
		return nil
	}

	var wasCut bool
	if oldData, ok := s.queue[offset]; ok {
		if len(data) <= len(oldData) {
			return errDuplicateStreamData
		}
		data = data[len(oldData):]
		offset += protocol.ByteCount(len(oldData))
		wasCut = true
	}

	start := offset
	end := offset + protocol.ByteCount(len(data))

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
		offset += add
		start += add
		data = data[add:]
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
		delete(s.queue, endGap.Value.End)
		endGap = nextEndGap
	}

	if end > endGap.Value.End {
		cutLen := end - endGap.Value.End
		len := protocol.ByteCount(len(data)) - cutLen
		end -= cutLen
		data = data[:len]
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
		return errors.New("Too many gaps in received data")
	}

	if wasCut {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
	}

	s.queue[offset] = data
	return nil
}

func (s *frameSorter) Pop() ([]byte /* data */, bool /* fin */) {
	data, ok := s.queue[s.readPos]
	if !ok {
		return nil, s.readPos >= s.finalOffset
	}
	delete(s.queue, s.readPos)
	s.readPos += protocol.ByteCount(len(data))
	return data, s.readPos >= s.finalOffset
}
