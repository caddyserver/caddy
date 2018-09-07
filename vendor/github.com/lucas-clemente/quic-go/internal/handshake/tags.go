package handshake

// A Tag in the QUIC crypto
type Tag uint32

const (
	// TagCHLO is a client hello
	TagCHLO Tag = 'C' + 'H'<<8 + 'L'<<16 + 'O'<<24
	// TagREJ is a server hello rejection
	TagREJ Tag = 'R' + 'E'<<8 + 'J'<<16
	// TagSCFG is a server config
	TagSCFG Tag = 'S' + 'C'<<8 + 'F'<<16 + 'G'<<24

	// TagPAD is padding
	TagPAD Tag = 'P' + 'A'<<8 + 'D'<<16
	// TagSNI is the server name indication
	TagSNI Tag = 'S' + 'N'<<8 + 'I'<<16
	// TagVER is the QUIC version
	TagVER Tag = 'V' + 'E'<<8 + 'R'<<16
	// TagCCS are the hashes of the common certificate sets
	TagCCS Tag = 'C' + 'C'<<8 + 'S'<<16
	// TagCCRT are the hashes of the cached certificates
	TagCCRT Tag = 'C' + 'C'<<8 + 'R'<<16 + 'T'<<24
	// TagMSPC is max streams per connection
	TagMSPC Tag = 'M' + 'S'<<8 + 'P'<<16 + 'C'<<24
	// TagMIDS is max incoming dyanamic streams
	TagMIDS Tag = 'M' + 'I'<<8 + 'D'<<16 + 'S'<<24
	// TagUAID is the user agent ID
	TagUAID Tag = 'U' + 'A'<<8 + 'I'<<16 + 'D'<<24
	// TagSVID is the server ID (unofficial tag by us :)
	TagSVID Tag = 'S' + 'V'<<8 + 'I'<<16 + 'D'<<24
	// TagTCID is truncation of the connection ID
	TagTCID Tag = 'T' + 'C'<<8 + 'I'<<16 + 'D'<<24
	// TagPDMD is the proof demand
	TagPDMD Tag = 'P' + 'D'<<8 + 'M'<<16 + 'D'<<24
	// TagSRBF is the socket receive buffer
	TagSRBF Tag = 'S' + 'R'<<8 + 'B'<<16 + 'F'<<24
	// TagICSL is the idle connection state lifetime
	TagICSL Tag = 'I' + 'C'<<8 + 'S'<<16 + 'L'<<24
	// TagNONP is the client proof nonce
	TagNONP Tag = 'N' + 'O'<<8 + 'N'<<16 + 'P'<<24
	// TagSCLS is the silently close timeout
	TagSCLS Tag = 'S' + 'C'<<8 + 'L'<<16 + 'S'<<24
	// TagCSCT is the signed cert timestamp (RFC6962) of leaf cert
	TagCSCT Tag = 'C' + 'S'<<8 + 'C'<<16 + 'T'<<24
	// TagCOPT are the connection options
	TagCOPT Tag = 'C' + 'O'<<8 + 'P'<<16 + 'T'<<24
	// TagCFCW is the initial session/connection flow control receive window
	TagCFCW Tag = 'C' + 'F'<<8 + 'C'<<16 + 'W'<<24
	// TagSFCW is the initial stream flow control receive window.
	TagSFCW Tag = 'S' + 'F'<<8 + 'C'<<16 + 'W'<<24

	// TagNSTP is the no STOP_WAITING experiment
	// currently unsupported by quic-go
	TagNSTP Tag = 'N' + 'S'<<8 + 'T'<<16 + 'P'<<24

	// TagSTK is the source-address token
	TagSTK Tag = 'S' + 'T'<<8 + 'K'<<16
	// TagSNO is the server nonce
	TagSNO Tag = 'S' + 'N'<<8 + 'O'<<16
	// TagPROF is the server proof
	TagPROF Tag = 'P' + 'R'<<8 + 'O'<<16 + 'F'<<24

	// TagNONC is the client nonce
	TagNONC Tag = 'N' + 'O'<<8 + 'N'<<16 + 'C'<<24
	// TagXLCT is the expected leaf certificate
	TagXLCT Tag = 'X' + 'L'<<8 + 'C'<<16 + 'T'<<24

	// TagSCID is the server config ID
	TagSCID Tag = 'S' + 'C'<<8 + 'I'<<16 + 'D'<<24
	// TagKEXS is the list of key exchange algos
	TagKEXS Tag = 'K' + 'E'<<8 + 'X'<<16 + 'S'<<24
	// TagAEAD is the list of AEAD algos
	TagAEAD Tag = 'A' + 'E'<<8 + 'A'<<16 + 'D'<<24
	// TagPUBS is the public value for the KEX
	TagPUBS Tag = 'P' + 'U'<<8 + 'B'<<16 + 'S'<<24
	// TagOBIT is the client orbit
	TagOBIT Tag = 'O' + 'B'<<8 + 'I'<<16 + 'T'<<24
	// TagEXPY is the server config expiry
	TagEXPY Tag = 'E' + 'X'<<8 + 'P'<<16 + 'Y'<<24
	// TagCERT is the CERT data
	TagCERT Tag = 0xff545243

	// TagSHLO is the server hello
	TagSHLO Tag = 'S' + 'H'<<8 + 'L'<<16 + 'O'<<24

	// TagPRST is the public reset tag
	TagPRST Tag = 'P' + 'R'<<8 + 'S'<<16 + 'T'<<24
	// TagRSEQ is the public reset rejected packet number
	TagRSEQ Tag = 'R' + 'S'<<8 + 'E'<<16 + 'Q'<<24
	// TagRNON is the public reset nonce
	TagRNON Tag = 'R' + 'N'<<8 + 'O'<<16 + 'N'<<24
)
