# Changelog

## v0.10.0 (2018-08-28)

- Add support for QUIC 44, drop support for QUIC 42.

## v0.9.0 (2018-08-15)

- Add a `quic.Config` option for the length of the connection ID (for IETF QUIC).
- Split Session.Close into one method for regular closing and one for closing with an error.

## v0.8.0 (2018-06-26)

- Add support for unidirectional streams (for IETF QUIC).
- Add a `quic.Config` option for the maximum number of incoming streams.
- Add support for QUIC 42 and 43.
- Add dial functions that use a context.
- Multiplex clients on a net.PacketConn, when using Dial(conn).

## v0.7.0 (2018-02-03)

- The lower boundary for packets included in ACKs is now derived, and the value sent in STOP_WAITING frames is ignored.
- Remove `DialNonFWSecure` and `DialAddrNonFWSecure`.
- Expose the `ConnectionState` in the `Session` (experimental API).
- Implement packet pacing.

## v0.6.0 (2017-12-12)

- Add support for QUIC 39, drop support for QUIC 35 - 37
- Added `quic.Config` options for maximal flow control windows
- Add a `quic.Config` option for QUIC versions
- Add a `quic.Config` option to request omission of the connection ID from a server
- Add a `quic.Config` option to configure the source address validation
- Add a `quic.Config` option to configure the handshake timeout
- Add a `quic.Config` option to configure the idle timeout
- Add a `quic.Config` option to configure keep-alive
- Rename the STK to Cookie
- Implement `net.Conn`-style deadlines for streams
- Remove the `tls.Config` from the `quic.Config`. The `tls.Config` must now be passed to the `Dial` and `Listen` functions as a separate parameter. See the [Godoc](https://godoc.org/github.com/lucas-clemente/quic-go) for details.
- Changed the log level environment variable to only accept strings ("DEBUG", "INFO", "ERROR"), see [the wiki](https://github.com/lucas-clemente/quic-go/wiki/Logging) for more details.
- Rename the `h2quic.QuicRoundTripper` to `h2quic.RoundTripper`
- Changed `h2quic.Server.Serve()` to accept a `net.PacketConn`
- Drop support for Go 1.7 and 1.8.
- Various bugfixes
