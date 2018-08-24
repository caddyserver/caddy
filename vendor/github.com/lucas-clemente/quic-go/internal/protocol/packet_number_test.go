package protocol

import (
	"fmt"
	"math"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Tests taken and extended from chrome
var _ = Describe("packet number calculation", func() {
	Context("infering a packet number", func() {
		getEpoch := func(len PacketNumberLen, v VersionNumber) uint64 {
			if v.UsesVarintPacketNumbers() {
				switch len {
				case PacketNumberLen1:
					return uint64(1) << 7
				case PacketNumberLen2:
					return uint64(1) << 14
				case PacketNumberLen4:
					return uint64(1) << 30
				default:
					Fail("invalid packet number len")
				}
			}
			return uint64(1) << (len * 8)
		}
		check := func(length PacketNumberLen, expected, last uint64, v VersionNumber) {
			epoch := getEpoch(length, v)
			epochMask := epoch - 1
			wirePacketNumber := expected & epochMask
			Expect(InferPacketNumber(length, PacketNumber(last), PacketNumber(wirePacketNumber), v)).To(Equal(PacketNumber(expected)))
		}

		for _, v := range []VersionNumber{Version39, VersionTLS} {
			version := v

			Context(fmt.Sprintf("using varint packet numbers: %t", version.UsesVarintPacketNumbers()), func() {
				for _, l := range []PacketNumberLen{PacketNumberLen1, PacketNumberLen2, PacketNumberLen4} {
					length := l

					Context(fmt.Sprintf("with %d bytes", length), func() {
						epoch := getEpoch(length, version)
						epochMask := epoch - 1

						It("works near epoch start", func() {
							// A few quick manual sanity check
							check(length, 1, 0, version)
							check(length, epoch+1, epochMask, version)
							check(length, epoch, epochMask, version)

							// Cases where the last number was close to the start of the range.
							for last := uint64(0); last < 10; last++ {
								// Small numbers should not wrap (even if they're out of order).
								for j := uint64(0); j < 10; j++ {
									check(length, j, last, version)
								}

								// Large numbers should not wrap either (because we're near 0 already).
								for j := uint64(0); j < 10; j++ {
									check(length, epoch-1-j, last, version)
								}
							}
						})

						It("works near epoch end", func() {
							// Cases where the last number was close to the end of the range
							for i := uint64(0); i < 10; i++ {
								last := epoch - i

								// Small numbers should wrap.
								for j := uint64(0); j < 10; j++ {
									check(length, epoch+j, last, version)
								}

								// Large numbers should not (even if they're out of order).
								for j := uint64(0); j < 10; j++ {
									check(length, epoch-1-j, last, version)
								}
							}
						})

						// Next check where we're in a non-zero epoch to verify we handle
						// reverse wrapping, too.
						It("works near previous epoch", func() {
							prevEpoch := 1 * epoch
							curEpoch := 2 * epoch
							// Cases where the last number was close to the start of the range
							for i := uint64(0); i < 10; i++ {
								last := curEpoch + i
								// Small number should not wrap (even if they're out of order).
								for j := uint64(0); j < 10; j++ {
									check(length, curEpoch+j, last, version)
								}

								// But large numbers should reverse wrap.
								for j := uint64(0); j < 10; j++ {
									num := epoch - 1 - j
									check(length, prevEpoch+num, last, version)
								}
							}
						})

						It("works near next epoch", func() {
							curEpoch := 2 * epoch
							nextEpoch := 3 * epoch
							// Cases where the last number was close to the end of the range
							for i := uint64(0); i < 10; i++ {
								last := nextEpoch - 1 - i

								// Small numbers should wrap.
								for j := uint64(0); j < 10; j++ {
									check(length, nextEpoch+j, last, version)
								}

								// but large numbers should not (even if they're out of order).
								for j := uint64(0); j < 10; j++ {
									num := epoch - 1 - j
									check(length, curEpoch+num, last, version)
								}
							}
						})

						It("works near next max", func() {
							maxNumber := uint64(math.MaxUint64)
							maxEpoch := maxNumber & ^epochMask

							// Cases where the last number was close to the end of the range
							for i := uint64(0); i < 10; i++ {
								// Subtract 1, because the expected next packet number is 1 more than the
								// last packet number.
								last := maxNumber - i - 1

								// Small numbers should not wrap, because they have nowhere to go.
								for j := uint64(0); j < 10; j++ {
									check(length, maxEpoch+j, last, version)
								}

								// Large numbers should not wrap either.
								for j := uint64(0); j < 10; j++ {
									num := epoch - 1 - j
									check(length, maxEpoch+num, last, version)
								}
							}
						})
					})
				}

				Context("shortening a packet number for the header", func() {
					Context("shortening", func() {
						It("sends out low packet numbers as 2 byte", func() {
							length := GetPacketNumberLengthForHeader(4, 2, version)
							Expect(length).To(Equal(PacketNumberLen2))
						})

						It("sends out high packet numbers as 2 byte, if all ACKs are received", func() {
							length := GetPacketNumberLengthForHeader(0xdeadbeef, 0xdeadbeef-1, version)
							Expect(length).To(Equal(PacketNumberLen2))
						})

						It("sends out higher packet numbers as 4 bytes, if a lot of ACKs are missing", func() {
							length := GetPacketNumberLengthForHeader(40000, 2, version)
							Expect(length).To(Equal(PacketNumberLen4))
						})
					})

					Context("self-consistency", func() {
						It("works for small packet numbers", func() {
							for i := uint64(1); i < 10000; i++ {
								packetNumber := PacketNumber(i)
								leastUnacked := PacketNumber(1)
								length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked, version)
								wirePacketNumber := (uint64(packetNumber) << (64 - length*8)) >> (64 - length*8)

								inferedPacketNumber := InferPacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber), version)
								Expect(inferedPacketNumber).To(Equal(packetNumber))
							}
						})

						It("works for small packet numbers and increasing ACKed packets", func() {
							for i := uint64(1); i < 10000; i++ {
								packetNumber := PacketNumber(i)
								leastUnacked := PacketNumber(i / 2)
								length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked, version)
								epochMask := getEpoch(length, version) - 1
								wirePacketNumber := uint64(packetNumber) & epochMask

								inferedPacketNumber := InferPacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber), version)
								Expect(inferedPacketNumber).To(Equal(packetNumber))
							}
						})

						It("also works for larger packet numbers", func() {
							var increment uint64
							for i := uint64(1); i < getEpoch(PacketNumberLen4, version); i += increment {
								packetNumber := PacketNumber(i)
								leastUnacked := PacketNumber(1)
								length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked, version)
								epochMask := getEpoch(length, version) - 1
								wirePacketNumber := uint64(packetNumber) & epochMask

								inferedPacketNumber := InferPacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber), version)
								Expect(inferedPacketNumber).To(Equal(packetNumber))

								increment = getEpoch(length, version) / 8
							}
						})

						It("works for packet numbers larger than 2^48", func() {
							for i := (uint64(1) << 48); i < ((uint64(1) << 63) - 1); i += (uint64(1) << 48) {
								packetNumber := PacketNumber(i)
								leastUnacked := PacketNumber(i - 1000)
								length := GetPacketNumberLengthForHeader(packetNumber, leastUnacked, version)
								wirePacketNumber := (uint64(packetNumber) << (64 - length*8)) >> (64 - length*8)

								inferedPacketNumber := InferPacketNumber(length, leastUnacked, PacketNumber(wirePacketNumber), version)
								Expect(inferedPacketNumber).To(Equal(packetNumber))
							}
						})
					})
				})
			})
		}
	})

	Context("determining the minimum length of a packet number", func() {
		It("1 byte", func() {
			Expect(GetPacketNumberLength(0xFF)).To(Equal(PacketNumberLen1))
		})

		It("2 byte", func() {
			Expect(GetPacketNumberLength(0xFFFF)).To(Equal(PacketNumberLen2))
		})

		It("4 byte", func() {
			Expect(GetPacketNumberLength(0xFFFFFFFF)).To(Equal(PacketNumberLen4))
		})

		It("6 byte", func() {
			Expect(GetPacketNumberLength(0xFFFFFFFFFFFF)).To(Equal(PacketNumberLen6))
		})
	})
})
