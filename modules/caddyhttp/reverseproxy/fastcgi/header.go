package fastcgi

type header struct {
	Version       uint8
	Type          uint8
	ID            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

func (h *header) init(recType uint8, reqID uint16, contentLength int) {
	h.Version = 1
	h.Type = recType
	h.ID = reqID
	h.ContentLength = uint16(contentLength)
	h.PaddingLength = uint8(-contentLength & 7)
}
