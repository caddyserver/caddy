// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
