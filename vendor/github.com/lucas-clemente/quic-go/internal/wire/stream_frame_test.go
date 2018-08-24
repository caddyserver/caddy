package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM frame (for IETF QUIC)", func() {
	Context("when parsing", func() {
		It("parses a frame with OFF bit", func() {
			data := []byte{0x10 ^ 0x4}
			data = append(data, encodeVarInt(0x12345)...)    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.Offset).To(Equal(protocol.ByteCount(0xdecafbad)))
			Expect(r.Len()).To(BeZero())
		})

		It("respects the LEN when parsing the frame", func() {
			data := []byte{0x10 ^ 0x2}
			data = append(data, encodeVarInt(0x12345)...) // stream ID
			data = append(data, encodeVarInt(4)...)       // data length
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0x12345)))
			Expect(frame.Data).To(Equal([]byte("foob")))
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(Equal(2))
		})

		It("parses a frame with FIN bit", func() {
			data := []byte{0x10 ^ 0x1}
			data = append(data, encodeVarInt(9)...) // stream ID
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			frame, err := parseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(9)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
			Expect(frame.FinBit).To(BeTrue())
			Expect(frame.Offset).To(BeZero())
			Expect(r.Len()).To(BeZero())
		})

		It("allows empty frames", func() {
			data := []byte{0x10 ^ 0x4}
			data = append(data, encodeVarInt(0x1337)...)  // stream ID
			data = append(data, encodeVarInt(0x12345)...) // offset
			r := bytes.NewReader(data)
			f, err := parseStreamFrame(r, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.StreamID).To(Equal(protocol.StreamID(0x1337)))
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x12345)))
			Expect(f.Data).To(BeEmpty())
			Expect(f.FinBit).To(BeFalse())
		})

		It("rejects frames that overflow the maximum offset", func() {
			data := []byte{0x10 ^ 0x4}
			data = append(data, encodeVarInt(0x12345)...)                         // stream ID
			data = append(data, encodeVarInt(uint64(protocol.MaxByteCount-5))...) // offset
			data = append(data, []byte("foobar")...)
			r := bytes.NewReader(data)
			_, err := parseStreamFrame(r, versionIETFFrames)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidStreamData, "data overflows maximum offset")))
		})

		It("errors on EOFs", func() {
			data := []byte{0x10 ^ 0x4 ^ 0x2}
			data = append(data, encodeVarInt(0x12345)...)    // stream ID
			data = append(data, encodeVarInt(0xdecafbad)...) // offset
			data = append(data, encodeVarInt(6)...)          // data length
			data = append(data, []byte("foobar")...)
			_, err := parseStreamFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseStreamFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame without offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				Data:     []byte("foobar"),
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with FIN bit", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x123456,
				FinBit:   true,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4 ^ 0x1}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...) // stream ID
			expected = append(expected, encodeVarInt(6)...)      // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame with data length and offset", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Data:           []byte("foobar"),
				DataLenPresent: true,
				Offset:         0x123456,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x10 ^ 0x4 ^ 0x2}
			expected = append(expected, encodeVarInt(0x1337)...)   // stream ID
			expected = append(expected, encodeVarInt(0x123456)...) // offset
			expected = append(expected, encodeVarInt(6)...)        // data length
			expected = append(expected, []byte("foobar")...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("refuses to write an empty frame without FIN", func() {
			f := &StreamFrame{
				StreamID: 0x42,
				Offset:   0x1337,
			}
			b := &bytes.Buffer{}
			err := f.Write(b, versionIETFFrames)
			Expect(err).To(MatchError("StreamFrame: attempting to write empty frame without FIN"))
		})
	})

	Context("length", func() {
		It("has the right length for a frame without offset and data length", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Data:     []byte("foobar"),
			}
			Expect(f.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + 6))
		})

		It("has the right length for a frame with offset", func() {
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0x42,
				Data:     []byte("foobar"),
			}
			Expect(f.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0x42) + 6))
		})

		It("has the right length for a frame with data length", func() {
			f := &StreamFrame{
				StreamID:       0x1337,
				Offset:         0x1234567,
				DataLenPresent: true,
				Data:           []byte("foobar"),
			}
			Expect(f.Length(versionIETFFrames)).To(Equal(1 + utils.VarIntLen(0x1337) + utils.VarIntLen(0x1234567) + utils.VarIntLen(6) + 6))
		})
	})

	Context("max data length", func() {
		const maxSize = 3000

		It("always returns a data length such that the resulting frame has the right size, if data length is not present", func() {
			data := make([]byte, maxSize)
			f := &StreamFrame{
				StreamID: 0x1337,
				Offset:   0xdeadbeef,
			}
			b := &bytes.Buffer{}
			for i := 1; i < 3000; i++ {
				b.Reset()
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i), versionIETFFrames)
				if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
					// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
					f.Data = []byte{0}
					err := f.Write(b, versionIETFFrames)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(BeNumerically(">", i))
					continue
				}
				f.Data = data[:int(maxDataLen)]
				err := f.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(i))
			}
		})

		It("always returns a data length such that the resulting frame has the right size, if data length is present", func() {
			data := make([]byte, maxSize)
			f := &StreamFrame{
				StreamID:       0x1337,
				Offset:         0xdeadbeef,
				DataLenPresent: true,
			}
			b := &bytes.Buffer{}
			var frameOneByteTooSmallCounter int
			for i := 1; i < 3000; i++ {
				b.Reset()
				f.Data = nil
				maxDataLen := f.MaxDataLen(protocol.ByteCount(i), versionIETFFrames)
				if maxDataLen == 0 { // 0 means that no valid STREAM frame can be written
					// check that writing a minimal size STREAM frame (i.e. with 1 byte data) is actually larger than the desired size
					f.Data = []byte{0}
					err := f.Write(b, versionIETFFrames)
					Expect(err).ToNot(HaveOccurred())
					Expect(b.Len()).To(BeNumerically(">", i))
					continue
				}
				f.Data = data[:int(maxDataLen)]
				err := f.Write(b, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				// There's *one* pathological case, where a data length of x can be encoded into 1 byte
				// but a data lengths of x+1 needs 2 bytes
				// In that case, it's impossible to create a STREAM frame of the desired size
				if b.Len() == i-1 {
					frameOneByteTooSmallCounter++
					continue
				}
				Expect(b.Len()).To(Equal(i))
			}
			Expect(frameOneByteTooSmallCounter).To(Equal(1))
		})
	})

	Context("splitting", func() {
		for _, v := range []protocol.VersionNumber{versionBigEndian, versionIETFFrames} {
			version := v

			It("doesn't split if the frame is short enough", func() {
				f := &StreamFrame{
					StreamID:       0x1337,
					DataLenPresent: true,
					Offset:         0xdeadbeef,
					Data:           make([]byte, 100),
				}
				newFrame, err := f.MaybeSplitOffFrame(f.Length(version), version)
				Expect(err).ToNot(HaveOccurred())
				Expect(newFrame).To(BeNil())
				newFrame, err = f.MaybeSplitOffFrame(f.Length(version)-1, version)
				Expect(err).ToNot(HaveOccurred())
				Expect(newFrame).ToNot(BeNil())
			})

			It("keeps the data len", func() {
				f := &StreamFrame{
					StreamID:       0x1337,
					DataLenPresent: true,
					Data:           make([]byte, 100),
				}
				newFrame, err := f.MaybeSplitOffFrame(66, version)
				Expect(err).ToNot(HaveOccurred())
				Expect(newFrame).ToNot(BeNil())
				Expect(f.DataLenPresent).To(BeTrue())
				Expect(newFrame.DataLenPresent).To(BeTrue())
			})

			It("adjusts the offset", func() {
				f := &StreamFrame{
					StreamID: 0x1337,
					Offset:   0x100,
					Data:     []byte("foobar"),
				}
				newFrame, err := f.MaybeSplitOffFrame(f.Length(version)-3, version)
				Expect(err).ToNot(HaveOccurred())
				Expect(newFrame).ToNot(BeNil())
				Expect(newFrame.Offset).To(Equal(protocol.ByteCount(0x100)))
				Expect(newFrame.Data).To(Equal([]byte("foo")))
				Expect(f.Offset).To(Equal(protocol.ByteCount(0x100 + 3)))
				Expect(f.Data).To(Equal([]byte("bar")))
			})

			It("preserves the FIN bit", func() {
				f := &StreamFrame{
					StreamID: 0x1337,
					FinBit:   true,
					Offset:   0xdeadbeef,
					Data:     make([]byte, 100),
				}
				newFrame, err := f.MaybeSplitOffFrame(50, version)
				Expect(err).ToNot(HaveOccurred())
				Expect(newFrame).ToNot(BeNil())
				Expect(newFrame.Offset).To(BeNumerically("<", f.Offset))
				Expect(f.FinBit).To(BeTrue())
				Expect(newFrame.FinBit).To(BeFalse())
			})

			It("produces frames of the correct length, without data len", func() {
				const size = 1000
				f := &StreamFrame{
					StreamID: 0xdecafbad,
					Offset:   0x1234,
					Data:     []byte{0},
				}
				minFrameSize := f.Length(version)
				for i := protocol.ByteCount(0); i < minFrameSize; i++ {
					_, err := f.MaybeSplitOffFrame(i, version)
					Expect(err).To(HaveOccurred())
				}
				for i := minFrameSize; i < size; i++ {
					f.Data = make([]byte, size)
					newFrame, err := f.MaybeSplitOffFrame(i, version)
					Expect(err).ToNot(HaveOccurred())
					Expect(newFrame.Length(version)).To(Equal(i))
				}
			})
		}

		It("produces frames of the correct length, with data len", func() {
			const size = 1000
			f := &StreamFrame{
				StreamID:       0xdecafbad,
				Offset:         0x1234,
				DataLenPresent: true,
				Data:           []byte{0},
			}
			minFrameSize := f.Length(versionIETFFrames)
			for i := protocol.ByteCount(0); i < minFrameSize; i++ {
				_, err := f.MaybeSplitOffFrame(i, versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
			var frameOneByteTooSmallCounter int
			for i := minFrameSize; i < size; i++ {
				f.Data = make([]byte, size)
				newFrame, err := f.MaybeSplitOffFrame(i, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				// There's *one* pathological case, where a data length of x can be encoded into 1 byte
				// but a data lengths of x+1 needs 2 bytes
				// In that case, it's impossible to create a STREAM frame of the desired size
				if newFrame.Length(versionIETFFrames) == i-1 {
					frameOneByteTooSmallCounter++
					continue
				}
				Expect(newFrame.Length(versionIETFFrames)).To(Equal(i))
			}
			Expect(frameOneByteTooSmallCounter).To(Equal(1))
		})
	})
})
