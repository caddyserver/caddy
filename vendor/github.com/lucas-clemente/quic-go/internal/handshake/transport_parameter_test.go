package handshake

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport Parameters", func() {
	Context("for gQUIC", func() {
		Context("parsing", func() {
			It("sets all values", func() {
				values := map[Tag][]byte{
					TagSFCW: {0xad, 0xfb, 0xca, 0xde},
					TagCFCW: {0xef, 0xbe, 0xad, 0xde},
					TagICSL: {0x0d, 0xf0, 0xad, 0xba},
					TagMIDS: {0xff, 0x10, 0x00, 0xc0},
				}
				params, err := readHelloMap(values)
				Expect(err).ToNot(HaveOccurred())
				Expect(params.StreamFlowControlWindow).To(Equal(protocol.ByteCount(0xdecafbad)))
				Expect(params.ConnectionFlowControlWindow).To(Equal(protocol.ByteCount(0xdeadbeef)))
				Expect(params.IdleTimeout).To(Equal(time.Duration(0xbaadf00d) * time.Second))
				Expect(params.MaxStreams).To(Equal(uint32(0xc00010ff)))
				Expect(params.OmitConnectionID).To(BeFalse())
			})

			It("reads if the connection ID should be omitted", func() {
				values := map[Tag][]byte{TagTCID: {0, 0, 0, 0}}
				params, err := readHelloMap(values)
				Expect(err).ToNot(HaveOccurred())
				Expect(params.OmitConnectionID).To(BeTrue())
			})

			It("doesn't allow idle timeouts below the minimum remote idle timeout", func() {
				t := 2 * time.Second
				Expect(t).To(BeNumerically("<", protocol.MinRemoteIdleTimeout))
				values := map[Tag][]byte{
					TagICSL: {uint8(t.Seconds()), 0, 0, 0},
				}
				params, err := readHelloMap(values)
				Expect(err).ToNot(HaveOccurred())
				Expect(params.IdleTimeout).To(Equal(protocol.MinRemoteIdleTimeout))
			})

			It("errors when given an invalid SFCW value", func() {
				values := map[Tag][]byte{TagSFCW: {2, 0, 0}} // 1 byte too short
				_, err := readHelloMap(values)
				Expect(err).To(MatchError(errMalformedTag))
			})

			It("errors when given an invalid CFCW value", func() {
				values := map[Tag][]byte{TagCFCW: {2, 0, 0}} // 1 byte too short
				_, err := readHelloMap(values)
				Expect(err).To(MatchError(errMalformedTag))
			})

			It("errors when given an invalid TCID value", func() {
				values := map[Tag][]byte{TagTCID: {2, 0, 0}} // 1 byte too short
				_, err := readHelloMap(values)
				Expect(err).To(MatchError(errMalformedTag))
			})

			It("errors when given an invalid ICSL value", func() {
				values := map[Tag][]byte{TagICSL: {2, 0, 0}} // 1 byte too short
				_, err := readHelloMap(values)
				Expect(err).To(MatchError(errMalformedTag))
			})

			It("errors when given an invalid MIDS value", func() {
				values := map[Tag][]byte{TagMIDS: {2, 0, 0}} // 1 byte too short
				_, err := readHelloMap(values)
				Expect(err).To(MatchError(errMalformedTag))
			})
		})

		Context("writing", func() {
			It("returns all necessary parameters ", func() {
				params := &TransportParameters{
					StreamFlowControlWindow:     0xdeadbeef,
					ConnectionFlowControlWindow: 0xdecafbad,
					IdleTimeout:                 0xbaaaaaad * time.Second,
					MaxStreams:                  0x1337,
				}
				entryMap := params.getHelloMap()
				Expect(entryMap).To(HaveLen(4))
				Expect(entryMap).ToNot(HaveKey(TagTCID))
				Expect(entryMap).To(HaveKeyWithValue(TagSFCW, []byte{0xef, 0xbe, 0xad, 0xde}))
				Expect(entryMap).To(HaveKeyWithValue(TagCFCW, []byte{0xad, 0xfb, 0xca, 0xde}))
				Expect(entryMap).To(HaveKeyWithValue(TagICSL, []byte{0xad, 0xaa, 0xaa, 0xba}))
				Expect(entryMap).To(HaveKeyWithValue(TagMIDS, []byte{0x37, 0x13, 0, 0}))
			})

			It("requests omission of the connection ID", func() {
				params := &TransportParameters{OmitConnectionID: true}
				entryMap := params.getHelloMap()
				Expect(entryMap).To(HaveKeyWithValue(TagTCID, []byte{0, 0, 0, 0}))
			})
		})
	})

	Context("for TLS", func() {
		It("has a string representation", func() {
			p := &TransportParameters{
				StreamFlowControlWindow:     0x1234,
				ConnectionFlowControlWindow: 0x4321,
				MaxBidiStreams:              1337,
				MaxUniStreams:               7331,
				IdleTimeout:                 42 * time.Second,
			}
			Expect(p.String()).To(Equal("&handshake.TransportParameters{StreamFlowControlWindow: 0x1234, ConnectionFlowControlWindow: 0x4321, MaxBidiStreams: 1337, MaxUniStreams: 7331, IdleTimeout: 42s}"))
		})

		Context("parsing", func() {
			var (
				params              *TransportParameters
				parameters          map[transportParameterID][]byte
				statelessResetToken []byte
			)

			marshal := func(p map[transportParameterID][]byte) []byte {
				b := &bytes.Buffer{}
				for id, val := range p {
					utils.BigEndian.WriteUint16(b, uint16(id))
					utils.BigEndian.WriteUint16(b, uint16(len(val)))
					b.Write(val)
				}
				return b.Bytes()
			}

			BeforeEach(func() {
				params = &TransportParameters{}
				statelessResetToken = bytes.Repeat([]byte{42}, 16)
				parameters = map[transportParameterID][]byte{
					initialMaxStreamDataParameterID:  {0x11, 0x22, 0x33, 0x44},
					initialMaxDataParameterID:        {0x22, 0x33, 0x44, 0x55},
					initialMaxBidiStreamsParameterID: {0x33, 0x44},
					initialMaxUniStreamsParameterID:  {0x44, 0x55},
					idleTimeoutParameterID:           {0x13, 0x37},
					maxPacketSizeParameterID:         {0x73, 0x31},
					disableMigrationParameterID:      {},
					statelessResetTokenParameterID:   statelessResetToken,
				}
			})
			It("reads parameters", func() {
				err := params.unmarshal(marshal(parameters))
				Expect(err).ToNot(HaveOccurred())
				Expect(params.StreamFlowControlWindow).To(Equal(protocol.ByteCount(0x11223344)))
				Expect(params.ConnectionFlowControlWindow).To(Equal(protocol.ByteCount(0x22334455)))
				Expect(params.MaxBidiStreams).To(Equal(uint16(0x3344)))
				Expect(params.MaxUniStreams).To(Equal(uint16(0x4455)))
				Expect(params.IdleTimeout).To(Equal(0x1337 * time.Second))
				Expect(params.OmitConnectionID).To(BeFalse())
				Expect(params.MaxPacketSize).To(Equal(protocol.ByteCount(0x7331)))
				Expect(params.DisableMigration).To(BeTrue())
				Expect(params.StatelessResetToken).To(Equal(statelessResetToken))
			})

			It("rejects the parameters if the idle_timeout is missing", func() {
				delete(parameters, idleTimeoutParameterID)
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("missing parameter"))
			})

			It("doesn't allow values below the minimum remote idle timeout", func() {
				t := 2 * time.Second
				Expect(t).To(BeNumerically("<", protocol.MinRemoteIdleTimeout))
				parameters[idleTimeoutParameterID] = []byte{0, uint8(t.Seconds())}
				err := params.unmarshal(marshal(parameters))
				Expect(err).ToNot(HaveOccurred())
				Expect(params.IdleTimeout).To(Equal(protocol.MinRemoteIdleTimeout))
			})

			It("rejects the parameters if the initial_max_stream_data has the wrong length", func() {
				parameters[initialMaxStreamDataParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for initial_max_stream_data: 3 (expected 4)"))
			})

			It("rejects the parameters if the initial_max_data has the wrong length", func() {
				parameters[initialMaxDataParameterID] = []byte{0x11, 0x22, 0x33} // should be 4 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for initial_max_data: 3 (expected 4)"))
			})

			It("rejects the parameters if the initial_max_stream_id_bidi has the wrong length", func() {
				parameters[initialMaxBidiStreamsParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for initial_max_stream_id_bidi: 3 (expected 2)"))
			})

			It("rejects the parameters if the initial_max_stream_id_bidi has the wrong length", func() {
				parameters[initialMaxUniStreamsParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for initial_max_stream_id_uni: 3 (expected 2)"))
			})

			It("rejects the parameters if the initial_idle_timeout has the wrong length", func() {
				parameters[idleTimeoutParameterID] = []byte{0x11, 0x22, 0x33} // should be 2 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for idle_timeout: 3 (expected 2)"))
			})

			It("rejects the parameters if max_packet_size has the wrong length", func() {
				parameters[maxPacketSizeParameterID] = []byte{0x11} // should be 2 bytes
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for max_packet_size: 1 (expected 2)"))
			})

			It("rejects max_packet_sizes smaller than 1200 bytes", func() {
				parameters[maxPacketSizeParameterID] = []byte{0x4, 0xaf} // 0x4af = 1199
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("invalid value for max_packet_size: 1199 (minimum 1200)"))
			})

			It("rejects the parameters if disable_connection_migration has the wrong length", func() {
				parameters[disableMigrationParameterID] = []byte{0x11} // should empty
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for disable_migration: 1 (expected empty)"))
			})

			It("rejects the parameters if the stateless_reset_token has the wrong length", func() {
				parameters[statelessResetTokenParameterID] = statelessResetToken[1:]
				err := params.unmarshal(marshal(parameters))
				Expect(err).To(MatchError("wrong length for stateless_reset_token: 15 (expected 16)"))
			})

			It("ignores unknown parameters", func() {
				parameters[1337] = []byte{42}
				err := params.unmarshal(marshal(parameters))
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("marshalling", func() {
			It("marshals", func() {
				params := &TransportParameters{
					StreamFlowControlWindow:     0xdeadbeef,
					ConnectionFlowControlWindow: 0xdecafbad,
					IdleTimeout:                 0xcafe * time.Second,
					MaxBidiStreams:              0x1234,
					MaxUniStreams:               0x4321,
					DisableMigration:            true,
					StatelessResetToken:         bytes.Repeat([]byte{100}, 16),
				}
				b := &bytes.Buffer{}
				params.marshal(b)

				p := &TransportParameters{}
				Expect(p.unmarshal(b.Bytes())).To(Succeed())
				Expect(p.StreamFlowControlWindow).To(Equal(params.StreamFlowControlWindow))
				Expect(p.ConnectionFlowControlWindow).To(Equal(params.ConnectionFlowControlWindow))
				Expect(p.MaxUniStreams).To(Equal(params.MaxUniStreams))
				Expect(p.MaxBidiStreams).To(Equal(params.MaxBidiStreams))
				Expect(p.IdleTimeout).To(Equal(params.IdleTimeout))
				Expect(p.DisableMigration).To(Equal(params.DisableMigration))
				Expect(p.StatelessResetToken).To(Equal(params.StatelessResetToken))
			})
		})
	})
})
