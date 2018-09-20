package syslog

import (
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

//The handler receive every syslog entry at Handle method
type Handler interface {
	Handle(format.LogParts, int64, error)
}

type LogPartsChannel chan format.LogParts

//The ChannelHandler will send all the syslog entries into the given channel
type ChannelHandler struct {
	channel LogPartsChannel
}

//NewChannelHandler returns a new ChannelHandler
func NewChannelHandler(channel LogPartsChannel) *ChannelHandler {
	handler := new(ChannelHandler)
	handler.SetChannel(channel)

	return handler
}

//The channel to be used
func (h *ChannelHandler) SetChannel(channel LogPartsChannel) {
	h.channel = channel
}

//Syslog entry receiver
func (h *ChannelHandler) Handle(logParts format.LogParts, messageLength int64, err error) {
	h.channel <- logParts
}
