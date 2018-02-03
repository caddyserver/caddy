package protocol

import "time"

// MaxPacketSize is the maximum packet size that we use for sending packets.
// It includes the QUIC packet header, but excludes the UDP and IP header.
const MaxPacketSize ByteCount = 1200

// NonForwardSecurePacketSizeReduction is the number of bytes a non forward-secure packet has to be smaller than a forward-secure packet
// This makes sure that those packets can always be retransmitted without splitting the contained StreamFrames
const NonForwardSecurePacketSizeReduction = 50

// DefaultMaxCongestionWindow is the default for the max congestion window
const DefaultMaxCongestionWindow = 1000

// InitialCongestionWindow is the initial congestion window in QUIC packets
const InitialCongestionWindow = 32

// MaxUndecryptablePackets limits the number of undecryptable packets that a
// session queues for later until it sends a public reset.
const MaxUndecryptablePackets = 10

// PublicResetTimeout is the time to wait before sending a Public Reset when receiving too many undecryptable packets during the handshake
// This timeout allows the Go scheduler to switch to the Go rountine that reads the crypto stream and to escalate the crypto
const PublicResetTimeout = 500 * time.Millisecond

// AckSendDelay is the maximum delay that can be applied to an ACK for a retransmittable packet
// This is the value Chromium is using
const AckSendDelay = 25 * time.Millisecond

// ReceiveStreamFlowControlWindow is the stream-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveStreamFlowControlWindow = (1 << 10) * 32 // 32 kB

// ReceiveConnectionFlowControlWindow is the connection-level flow control window for receiving data
// This is the value that Google servers are using
const ReceiveConnectionFlowControlWindow = (1 << 10) * 48 // 48 kB

// DefaultMaxReceiveStreamFlowControlWindowServer is the default maximum stream-level flow control window for receiving data, for the server
// This is the value that Google servers are using
const DefaultMaxReceiveStreamFlowControlWindowServer = 1 * (1 << 20) // 1 MB

// DefaultMaxReceiveConnectionFlowControlWindowServer is the default connection-level flow control window for receiving data, for the server
// This is the value that Google servers are using
const DefaultMaxReceiveConnectionFlowControlWindowServer = 1.5 * (1 << 20) // 1.5 MB

// DefaultMaxReceiveStreamFlowControlWindowClient is the default maximum stream-level flow control window for receiving data, for the client
// This is the value that Chromium is using
const DefaultMaxReceiveStreamFlowControlWindowClient = 6 * (1 << 20) // 6 MB

// DefaultMaxReceiveConnectionFlowControlWindowClient is the default connection-level flow control window for receiving data, for the client
// This is the value that Google servers are using
const DefaultMaxReceiveConnectionFlowControlWindowClient = 15 * (1 << 20) // 15 MB

// ConnectionFlowControlMultiplier determines how much larger the connection flow control windows needs to be relative to any stream's flow control window
// This is the value that Chromium is using
const ConnectionFlowControlMultiplier = 1.5

// WindowUpdateThreshold is the fraction of the receive window that has to be consumed before an higher offset is advertised to the client
const WindowUpdateThreshold = 0.25

// MaxIncomingStreams is the maximum number of streams that a peer may open
const MaxIncomingStreams = 100

// MaxStreamsMultiplier is the slack the client is allowed for the maximum number of streams per connection, needed e.g. when packets are out of order or dropped. The minimum of this procentual increase and the absolute increment specified by MaxStreamsMinimumIncrement is used.
const MaxStreamsMultiplier = 1.1

// MaxStreamsMinimumIncrement is the slack the client is allowed for the maximum number of streams per connection, needed e.g. when packets are out of order or dropped. The minimum of this absolute increment and the procentual increase specified by MaxStreamsMultiplier is used.
const MaxStreamsMinimumIncrement = 10

// MaxNewStreamIDDelta is the maximum difference between and a newly opened Stream and the highest StreamID that a client has ever opened
// note that the number of streams is half this value, since the client can only open streams with open StreamID
const MaxNewStreamIDDelta = 4 * MaxIncomingStreams

// MaxSessionUnprocessedPackets is the max number of packets stored in each session that are not yet processed.
const MaxSessionUnprocessedPackets = DefaultMaxCongestionWindow

// SkipPacketAveragePeriodLength is the average period length in which one packet number is skipped to prevent an Optimistic ACK attack
const SkipPacketAveragePeriodLength PacketNumber = 500

// MaxTrackedSkippedPackets is the maximum number of skipped packet numbers the SentPacketHandler keep track of for Optimistic ACK attack mitigation
const MaxTrackedSkippedPackets = 10

// CookieExpiryTime is the valid time of a cookie
const CookieExpiryTime = 24 * time.Hour

// MaxTrackedSentPackets is maximum number of sent packets saved for either later retransmission or entropy calculation
const MaxTrackedSentPackets = 2 * DefaultMaxCongestionWindow

// MaxTrackedReceivedAckRanges is the maximum number of ACK ranges tracked
const MaxTrackedReceivedAckRanges = DefaultMaxCongestionWindow

// MaxNonRetransmittableAcks is the maximum number of packets containing an ACK, but no retransmittable frames, that we send in a row
const MaxNonRetransmittableAcks = 19

// RetransmittablePacketsBeforeAck is the number of retransmittable that an ACK is sent for
const RetransmittablePacketsBeforeAck = 10

// MaxStreamFrameSorterGaps is the maximum number of gaps between received StreamFrames
// prevents DoS attacks against the streamFrameSorter
const MaxStreamFrameSorterGaps = 1000

// CryptoMaxParams is the upper limit for the number of parameters in a crypto message.
// Value taken from Chrome.
const CryptoMaxParams = 128

// CryptoParameterMaxLength is the upper limit for the length of a parameter in a crypto message.
const CryptoParameterMaxLength = 4000

// EphermalKeyLifetime is the lifetime of the ephermal key during the handshake, see handshake.getEphermalKEX.
const EphermalKeyLifetime = time.Minute

// MinRemoteIdleTimeout is the minimum value that we accept for the remote idle timeout
const MinRemoteIdleTimeout = 5 * time.Second

// DefaultIdleTimeout is the default idle timeout
const DefaultIdleTimeout = 30 * time.Second

// DefaultHandshakeTimeout is the default timeout for a connection until the crypto handshake succeeds.
const DefaultHandshakeTimeout = 10 * time.Second

// ClosedSessionDeleteTimeout the server ignores packets arriving on a connection that is already closed
// after this time all information about the old connection will be deleted
const ClosedSessionDeleteTimeout = time.Minute

// NumCachedCertificates is the number of cached compressed certificate chains, each taking ~1K space
const NumCachedCertificates = 128

// MinStreamFrameSize is the minimum size that has to be left in a packet, so that we add another STREAM frame.
// This avoids splitting up STREAM frames into small pieces, which has 2 advantages:
// 1. it reduces the framing overhead
// 2. it reduces the head-of-line blocking, when a packet is lost
const MinStreamFrameSize ByteCount = 128

// MinPacingDelay is the minimum duration that is used for packet pacing
// If the packet packing frequency is higher, multiple packets might be sent at once.
// Example: For a packet pacing delay of 20 microseconds, we would send 5 packets at once, wait for 100 microseconds, and so forth.
const MinPacingDelay time.Duration = 100 * time.Microsecond
