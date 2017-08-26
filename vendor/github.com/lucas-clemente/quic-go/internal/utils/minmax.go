package utils

import (
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
)

// InfDuration is a duration of infinite length
const InfDuration = time.Duration(math.MaxInt64)

// Max returns the maximum of two Ints
func Max(a, b int) int {
	if a < b {
		return b
	}
	return a
}

// MaxUint32 returns the maximum of two uint32
func MaxUint32(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

// MaxUint64 returns the maximum of two uint64
func MaxUint64(a, b uint64) uint64 {
	if a < b {
		return b
	}
	return a
}

// MinUint64 returns the maximum of two uint64
func MinUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// Min returns the minimum of two Ints
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MinUint32 returns the maximum of two uint32
func MinUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// MinInt64 returns the minimum of two int64
func MinInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// MaxInt64 returns the minimum of two int64
func MaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// MinByteCount returns the minimum of two ByteCounts
func MinByteCount(a, b protocol.ByteCount) protocol.ByteCount {
	if a < b {
		return a
	}
	return b
}

// MaxDuration returns the max duration
func MaxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// MinDuration returns the minimum duration
func MinDuration(a, b time.Duration) time.Duration {
	if a > b {
		return b
	}
	return a
}

// AbsDuration returns the absolute value of a time duration
func AbsDuration(d time.Duration) time.Duration {
	if d >= 0 {
		return d
	}
	return -d
}

// MinTime returns the earlier time
func MinTime(a, b time.Time) time.Time {
	if a.After(b) {
		return b
	}
	return a
}

// MaxPacketNumber returns the max packet number
func MaxPacketNumber(a, b protocol.PacketNumber) protocol.PacketNumber {
	if a > b {
		return a
	}
	return b
}

// MinPacketNumber returns the min packet number
func MinPacketNumber(a, b protocol.PacketNumber) protocol.PacketNumber {
	if a < b {
		return a
	}
	return b
}
