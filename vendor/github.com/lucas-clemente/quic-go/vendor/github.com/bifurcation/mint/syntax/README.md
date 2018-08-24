TLS Syntax
==========

TLS defines [its own syntax](https://tlswg.github.io/tls13-spec/#rfc.section.3)
for describing structures used in that protocol.  To facilitate experimentation
with TLS in Go, this module maps that syntax to the Go structure syntax, taking
advantage of Go's type annotations to encode non-type information carried in the
TLS presentation format.

For example, in the TLS specification, a ClientHello message has the following
structure:

~~~~~
uint16 ProtocolVersion;
opaque Random[32];
uint8 CipherSuite[2];
enum { ... (65535)} ExtensionType;

struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<0..2^16-1>;
} ClientHello;
~~~~~

This maps to the following Go type definitions:

~~~~~
type protocolVersion uint16
type random [32]byte
type cipherSuite uint16 // or [2]byte
type extensionType uint16

type extension struct {
  ExtensionType extensionType
  ExtensionData []byte `tls:"head=2"`
}

type clientHello struct {
	LegacyVersion            protocolVersion
	Random                   random
	LegacySessionID          []byte        `tls:"head=1,max=32"`
	CipherSuites             []cipherSuite `tls:"head=2,min=2"`
	LegacyCompressionMethods []byte        `tls:"head=1,min=1"`
	Extensions               []extension   `tls:"head=2"`
}
~~~~~

Then you can just declare, marshal, and unmarshal structs just like you would
with, say JSON.

The available annotations right now are all related to vectors:

* `head`: The number of bytes of length to use as a "header"
* `min`: The minimum length of the vector, in bytes
* `max`: The maximum length of the vector, in bytes

## Not supported

* The `select()` syntax for creating alternate version of the same struct (see,
  e.g., the KeyShare extension)

* The backreference syntax for array lengths or select parameters, as in `opaque
  fragment[TLSPlaintext.length]`.  Note, however, that in cases where the length
  immediately preceds the array, these can be reframed as vectors with
  appropriate sizes.
