# About the certificate

Yes, this folder contains a private key and a certificate for quic.clemente.io.

Unfortunately we need a valid certificate for the integration tests with Chrome and `quic_client`. No important data is served on the "real" `quic.clemente.io` (only a test page), and the MITM problem is imho negligible.

If you figure out a way to test with Chrome without having a cert and key here, let us now in an issue.
