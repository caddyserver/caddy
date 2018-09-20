package utils

import (
	"bytes"
	"io"
	"math"
)

// We define an unsigned 16-bit floating point value, inspired by IEEE floats
// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
// bit) and denormals, but without signs, transfinites or fractions. Wire format
// 16 bits (little-endian byte order) are split into exponent (high 5) and
// mantissa (low 11) and decoded as:
//   uint64_t value;
//   if (exponent == 0) value = mantissa;
//   else value = (mantissa | 1 << 11) << (exponent - 1)
const uFloat16ExponentBits = 5
const uFloat16MaxExponent = (1 << uFloat16ExponentBits) - 2                                        // 30
const uFloat16MantissaBits = 16 - uFloat16ExponentBits                                             // 11
const uFloat16MantissaEffectiveBits = uFloat16MantissaBits + 1                                     // 12
const uFloat16MaxValue = ((uint64(1) << uFloat16MantissaEffectiveBits) - 1) << uFloat16MaxExponent // 0x3FFC0000000

// readUfloat16 reads a float in the QUIC-float16 format and returns its uint64 representation
func readUfloat16(b io.ByteReader, byteOrder ByteOrder) (uint64, error) {
	val, err := byteOrder.ReadUint16(b)
	if err != nil {
		return 0, err
	}

	res := uint64(val)

	if res < (1 << uFloat16MantissaEffectiveBits) {
		// Fast path: either the value is denormalized (no hidden bit), or
		// normalized (hidden bit set, exponent offset by one) with exponent zero.
		// Zero exponent offset by one sets the bit exactly where the hidden bit is.
		// So in both cases the value encodes itself.
		return res, nil
	}

	exponent := val >> uFloat16MantissaBits // No sign extend on uint!
	// After the fast pass, the exponent is at least one (offset by one).
	// Un-offset the exponent.
	exponent--
	// Here we need to clear the exponent and set the hidden bit. We have already
	// decremented the exponent, so when we subtract it, it leaves behind the
	// hidden bit.
	res -= uint64(exponent) << uFloat16MantissaBits
	res <<= exponent
	return res, nil
}

// writeUfloat16 writes a float in the QUIC-float16 format from its uint64 representation
func writeUfloat16(b *bytes.Buffer, byteOrder ByteOrder, value uint64) {
	var result uint16
	if value < (uint64(1) << uFloat16MantissaEffectiveBits) {
		// Fast path: either the value is denormalized, or has exponent zero.
		// Both cases are represented by the value itself.
		result = uint16(value)
	} else if value >= uFloat16MaxValue {
		// Value is out of range; clamp it to the maximum representable.
		result = math.MaxUint16
	} else {
		// The highest bit is between position 13 and 42 (zero-based), which
		// corresponds to exponent 1-30. In the output, mantissa is from 0 to 10,
		// hidden bit is 11 and exponent is 11 to 15. Shift the highest bit to 11
		// and count the shifts.
		exponent := uint16(0)
		for offset := uint16(16); offset > 0; offset /= 2 {
			// Right-shift the value until the highest bit is in position 11.
			// For offset of 16, 8, 4, 2 and 1 (binary search over 1-30),
			// shift if the bit is at or above 11 + offset.
			if value >= (uint64(1) << (uFloat16MantissaBits + offset)) {
				exponent += offset
				value >>= offset
			}
		}

		// Hidden bit (position 11) is set. We should remove it and increment the
		// exponent. Equivalently, we just add it to the exponent.
		// This hides the bit.
		result = (uint16(value) + (exponent << uFloat16MantissaBits))
	}

	byteOrder.WriteUint16(b, result)
}
