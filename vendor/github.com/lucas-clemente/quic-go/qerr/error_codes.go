package qerr

// The error codes defined by QUIC
// Remember to run `go generate ./...` whenever the error codes change.
//go:generate stringer -type=ErrorCode
const (
	InternalError ErrorCode = 1
	// There were data frames after the a fin or reset.
	StreamDataAfterTermination ErrorCode = 2
	// Control frame is malformed.
	InvalidPacketHeader ErrorCode = 3
	// Frame data is malformed.
	InvalidFrameData ErrorCode = 4
	// The packet contained no payload.
	MissingPayload ErrorCode = 48
	// FEC data is malformed.
	InvalidFecData ErrorCode = 5
	// STREAM frame data is malformed.
	InvalidStreamData ErrorCode = 46
	// STREAM frame data overlaps with buffered data.
	OverlappingStreamData ErrorCode = 87
	// Received STREAM frame data is not encrypted.
	UnencryptedStreamData ErrorCode = 61
	// Attempt to send unencrypted STREAM frame.
	AttemptToSendUnencryptedStreamData ErrorCode = 88
	// FEC frame data is not encrypted.
	UnencryptedFecData ErrorCode = 77
	// RST_STREAM frame data is malformed.
	InvalidRstStreamData ErrorCode = 6
	// CONNECTION_CLOSE frame data is malformed.
	InvalidConnectionCloseData ErrorCode = 7
	// GOAWAY frame data is malformed.
	InvalidGoawayData ErrorCode = 8
	// WINDOW_UPDATE frame data is malformed.
	InvalidWindowUpdateData ErrorCode = 57
	// BLOCKED frame data is malformed.
	InvalidBlockedData ErrorCode = 58
	// STOP_WAITING frame data is malformed.
	InvalidStopWaitingData ErrorCode = 60
	// PATH_CLOSE frame data is malformed.
	InvalidPathCloseData ErrorCode = 78
	// ACK frame data is malformed.
	InvalidAckData ErrorCode = 9

	// Version negotiation packet is malformed.
	InvalidVersionNegotiationPacket ErrorCode = 10
	// Public RST packet is malformed.
	InvalidPublicRstPacket ErrorCode = 11
	// There was an error decrypting.
	DecryptionFailure ErrorCode = 12
	// There was an error encrypting.
	EncryptionFailure ErrorCode = 13
	// The packet exceeded kMaxPacketSize.
	PacketTooLarge ErrorCode = 14
	// The peer is going away.  May be a client or server.
	PeerGoingAway ErrorCode = 16
	// A stream ID was invalid.
	InvalidStreamID ErrorCode = 17
	// A priority was invalid.
	InvalidPriority ErrorCode = 49
	// Too many streams already open.
	TooManyOpenStreams ErrorCode = 18
	// The peer created too many available streams.
	TooManyAvailableStreams ErrorCode = 76
	// Received public reset for this connection.
	PublicReset ErrorCode = 19
	// Invalid protocol version.
	InvalidVersion ErrorCode = 20

	// The Header ID for a stream was too far from the previous.
	InvalidHeaderID ErrorCode = 22
	// Negotiable parameter received during handshake had invalid value.
	InvalidNegotiatedValue ErrorCode = 23
	// There was an error decompressing data.
	DecompressionFailure ErrorCode = 24
	// The connection timed out due to no network activity.
	NetworkIdleTimeout ErrorCode = 25
	// The connection timed out waiting for the handshake to complete.
	HandshakeTimeout ErrorCode = 67
	// There was an error encountered migrating addresses.
	ErrorMigratingAddress ErrorCode = 26
	// There was an error encountered migrating port only.
	ErrorMigratingPort ErrorCode = 86
	// There was an error while writing to the socket.
	PacketWriteError ErrorCode = 27
	// There was an error while reading from the socket.
	PacketReadError ErrorCode = 51
	// We received a STREAM_FRAME with no data and no fin flag set.
	EmptyStreamFrameNoFin ErrorCode = 50
	// We received invalid data on the headers stream.
	InvalidHeadersStreamData ErrorCode = 56
	// Invalid data on the headers stream received because of decompression
	// failure.
	HeadersStreamDataDecompressFailure ErrorCode = 97
	// The peer received too much data, violating flow control.
	FlowControlReceivedTooMuchData ErrorCode = 59
	// The peer sent too much data, violating flow control.
	FlowControlSentTooMuchData ErrorCode = 63
	// The peer received an invalid flow control window.
	FlowControlInvalidWindow ErrorCode = 64
	// The connection has been IP pooled into an existing connection.
	ConnectionIPPooled ErrorCode = 62
	// The connection has too many outstanding sent packets.
	TooManyOutstandingSentPackets ErrorCode = 68
	// The connection has too many outstanding received packets.
	TooManyOutstandingReceivedPackets ErrorCode = 69
	// The quic connection has been cancelled.
	ConnectionCancelled ErrorCode = 70
	// Disabled QUIC because of high packet loss rate.
	BadPacketLossRate ErrorCode = 71
	// Disabled QUIC because of too many PUBLIC_RESETs post handshake.
	PublicResetsPostHandshake ErrorCode = 73
	// Disabled QUIC because of too many timeouts with streams open.
	TimeoutsWithOpenStreams ErrorCode = 74
	// Closed because we failed to serialize a packet.
	FailedToSerializePacket ErrorCode = 75
	// QUIC timed out after too many RTOs.
	TooManyRtos ErrorCode = 85

	// Crypto errors.

	// Hanshake failed.
	HandshakeFailed ErrorCode = 28
	// Handshake message contained out of order tags.
	CryptoTagsOutOfOrder ErrorCode = 29
	// Handshake message contained too many entries.
	CryptoTooManyEntries ErrorCode = 30
	// Handshake message contained an invalid value length.
	CryptoInvalidValueLength ErrorCode = 31
	// A crypto message was received after the handshake was complete.
	CryptoMessageAfterHandshakeComplete ErrorCode = 32
	// A crypto message was received with an illegal message tag.
	InvalidCryptoMessageType ErrorCode = 33
	// A crypto message was received with an illegal parameter.
	InvalidCryptoMessageParameter ErrorCode = 34
	// An invalid channel id signature was supplied.
	InvalidChannelIDSignature ErrorCode = 52
	// A crypto message was received with a mandatory parameter missing.
	CryptoMessageParameterNotFound ErrorCode = 35
	// A crypto message was received with a parameter that has no overlap
	// with the local parameter.
	CryptoMessageParameterNoOverlap ErrorCode = 36
	// A crypto message was received that contained a parameter with too few
	// values.
	CryptoMessageIndexNotFound ErrorCode = 37
	// An internal error occurred in crypto processing.
	CryptoInternalError ErrorCode = 38
	// A crypto handshake message specified an unsupported version.
	CryptoVersionNotSupported ErrorCode = 39
	// A crypto handshake message resulted in a stateless reject.
	CryptoHandshakeStatelessReject ErrorCode = 72
	// There was no intersection between the crypto primitives supported by the
	// peer and ourselves.
	CryptoNoSupport ErrorCode = 40
	// The server rejected our client hello messages too many times.
	CryptoTooManyRejects ErrorCode = 41
	// The client rejected the server's certificate chain or signature.
	ProofInvalid ErrorCode = 42
	// A crypto message was received with a duplicate tag.
	CryptoDuplicateTag ErrorCode = 43
	// A crypto message was received with the wrong encryption level (i.e. it
	// should have been encrypted but was not.)
	CryptoEncryptionLevelIncorrect ErrorCode = 44
	// The server config for a server has expired.
	CryptoServerConfigExpired ErrorCode = 45
	// We failed to setup the symmetric keys for a connection.
	CryptoSymmetricKeySetupFailed ErrorCode = 53
	// A handshake message arrived, but we are still validating the
	// previous handshake message.
	CryptoMessageWhileValidatingClientHello ErrorCode = 54
	// A server config update arrived before the handshake is complete.
	CryptoUpdateBeforeHandshakeComplete ErrorCode = 65
	// This connection involved a version negotiation which appears to have been
	// tampered with.
	VersionNegotiationMismatch ErrorCode = 55

	// Multipath is not enabled, but a packet with multipath flag on is received.
	BadMultipathFlag ErrorCode = 79

	// IP address changed causing connection close.
	IPAddressChanged ErrorCode = 80

	// Connection migration errors.
	// Network changed, but connection had no migratable streams.
	ConnectionMigrationNoMigratableStreams ErrorCode = 81
	// Connection changed networks too many times.
	ConnectionMigrationTooManyChanges ErrorCode = 82
	// Connection migration was attempted, but there was no new network to
	// migrate to.
	ConnectionMigrationNoNewNetwork ErrorCode = 83
	// Network changed, but connection had one or more non-migratable streams.
	ConnectionMigrationNonMigratableStream ErrorCode = 84
)
