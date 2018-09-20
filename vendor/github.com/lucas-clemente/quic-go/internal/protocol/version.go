package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
)

// VersionNumber is a version number as int
type VersionNumber uint32

// gQUIC version range as defined in the wiki: https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
const (
	gquicVersion0   = 0x51303030
	maxGquicVersion = 0x51303439
)

// The version numbers, making grepping easier
const (
	Version39       VersionNumber = gquicVersion0 + 3*0x100 + 0x9
	Version43       VersionNumber = gquicVersion0 + 4*0x100 + 0x3
	Version44       VersionNumber = gquicVersion0 + 4*0x100 + 0x4
	VersionTLS      VersionNumber = 101
	VersionWhatever VersionNumber = 0 // for when the version doesn't matter
	VersionUnknown  VersionNumber = math.MaxUint32

	VersionMilestone0_10_0 VersionNumber = 0x51474f02
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []VersionNumber{
	Version44,
	Version43,
	Version39,
}

// IsValidVersion says if the version is known to quic-go
func IsValidVersion(v VersionNumber) bool {
	return v == VersionTLS || v == VersionMilestone0_10_0 || IsSupportedVersion(SupportedVersions, v)
}

// UsesTLS says if this QUIC version uses TLS 1.3 for the handshake
func (vn VersionNumber) UsesTLS() bool {
	return !vn.isGQUIC()
}

func (vn VersionNumber) String() string {
	switch vn {
	case VersionWhatever:
		return "whatever"
	case VersionUnknown:
		return "unknown"
	case VersionMilestone0_10_0:
		return "quic-go Milestone 0.10.0"
	case VersionTLS:
		return "TLS dev version (WIP)"
	default:
		if vn.isGQUIC() {
			return fmt.Sprintf("gQUIC %d", vn.toGQUICVersion())
		}
		return fmt.Sprintf("%#x", uint32(vn))
	}
}

// ToAltSvc returns the representation of the version for the H2 Alt-Svc parameters
func (vn VersionNumber) ToAltSvc() string {
	if vn.isGQUIC() {
		return fmt.Sprintf("%d", vn.toGQUICVersion())
	}
	return fmt.Sprintf("%d", vn)
}

// CryptoStreamID gets the Stream ID of the crypto stream
func (vn VersionNumber) CryptoStreamID() StreamID {
	if vn.isGQUIC() {
		return 1
	}
	return 0
}

// UsesIETFFrameFormat tells if this version uses the IETF frame format
func (vn VersionNumber) UsesIETFFrameFormat() bool {
	return !vn.isGQUIC()
}

// UsesIETFHeaderFormat tells if this version uses the IETF header format
func (vn VersionNumber) UsesIETFHeaderFormat() bool {
	return !vn.isGQUIC() || vn >= Version44
}

// UsesLengthInHeader tells if this version uses the Length field in the IETF header
func (vn VersionNumber) UsesLengthInHeader() bool {
	return !vn.isGQUIC()
}

// UsesTokenInHeader tells if this version uses the Token field in the IETF header
func (vn VersionNumber) UsesTokenInHeader() bool {
	return !vn.isGQUIC()
}

// UsesStopWaitingFrames tells if this version uses STOP_WAITING frames
func (vn VersionNumber) UsesStopWaitingFrames() bool {
	return vn.isGQUIC() && vn <= Version43
}

// UsesVarintPacketNumbers tells if this version uses 7/14/30 bit packet numbers
func (vn VersionNumber) UsesVarintPacketNumbers() bool {
	return !vn.isGQUIC()
}

// StreamContributesToConnectionFlowControl says if a stream contributes to connection-level flow control
func (vn VersionNumber) StreamContributesToConnectionFlowControl(id StreamID) bool {
	if id == vn.CryptoStreamID() {
		return false
	}
	if vn.isGQUIC() && id == 3 {
		return false
	}
	return true
}

func (vn VersionNumber) isGQUIC() bool {
	return vn > gquicVersion0 && vn <= maxGquicVersion
}

func (vn VersionNumber) toGQUICVersion() int {
	return int(10*(vn-gquicVersion0)/0x100) + int(vn%0x10)
}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []VersionNumber, v VersionNumber) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

// ChooseSupportedVersion finds the best version in the overlap of ours and theirs
// ours is a slice of versions that we support, sorted by our preference (descending)
// theirs is a slice of versions offered by the peer. The order does not matter.
// The bool returned indicates if a matching version was found.
func ChooseSupportedVersion(ours, theirs []VersionNumber) (VersionNumber, bool) {
	for _, ourVer := range ours {
		for _, theirVer := range theirs {
			if ourVer == theirVer {
				return ourVer, true
			}
		}
	}
	return 0, false
}

// generateReservedVersion generates a reserved version number (v & 0x0f0f0f0f == 0x0a0a0a0a)
func generateReservedVersion() VersionNumber {
	b := make([]byte, 4)
	_, _ = rand.Read(b) // ignore the error here. Failure to read random data doesn't break anything
	return VersionNumber((binary.BigEndian.Uint32(b) | 0x0a0a0a0a) & 0xfafafafa)
}

// GetGreasedVersions adds one reserved version number to a slice of version numbers, at a random position
func GetGreasedVersions(supported []VersionNumber) []VersionNumber {
	b := make([]byte, 1)
	_, _ = rand.Read(b) // ignore the error here. Failure to read random data doesn't break anything
	randPos := int(b[0]) % (len(supported) + 1)
	greased := make([]VersionNumber, len(supported)+1)
	copy(greased, supported[:randPos])
	greased[randPos] = generateReservedVersion()
	copy(greased[randPos+1:], supported[randPos:])
	return greased
}

// StripGreasedVersions strips all greased versions from a slice of versions
func StripGreasedVersions(versions []VersionNumber) []VersionNumber {
	realVersions := make([]VersionNumber, 0, len(versions))
	for _, v := range versions {
		if v&0x0f0f0f0f != 0x0a0a0a0a {
			realVersions = append(realVersions, v)
		}
	}
	return realVersions
}
