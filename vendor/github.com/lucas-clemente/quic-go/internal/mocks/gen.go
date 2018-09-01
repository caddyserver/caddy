package mocks

//go:generate sh -c "./mockgen_internal.sh mockhandshake handshake/mint_tls.go github.com/lucas-clemente/quic-go/internal/handshake MintTLS"
//go:generate sh -c "./mockgen_internal.sh mocks tls_extension_handler.go github.com/lucas-clemente/quic-go/internal/handshake TLSExtensionHandler"
//go:generate sh -c "./mockgen_internal.sh mocks stream_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol StreamFlowController"
//go:generate sh -c "./mockgen_internal.sh mockackhandler ackhandler/sent_packet_handler.go github.com/lucas-clemente/quic-go/internal/ackhandler SentPacketHandler"
//go:generate sh -c "./mockgen_internal.sh mockackhandler ackhandler/received_packet_handler.go github.com/lucas-clemente/quic-go/internal/ackhandler ReceivedPacketHandler"
//go:generate sh -c "./mockgen_internal.sh mocks congestion.go github.com/lucas-clemente/quic-go/internal/congestion SendAlgorithm"
//go:generate sh -c "./mockgen_internal.sh mocks connection_flow_controller.go github.com/lucas-clemente/quic-go/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "./mockgen_internal.sh mockcrypto crypto/aead.go github.com/lucas-clemente/quic-go/internal/crypto AEAD"
//go:generate sh -c "goimports -w ."
