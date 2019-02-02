package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// QuicCryptoKeyDerivationFunction is used for key derivation
type QuicCryptoKeyDerivationFunction func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte, pers protocol.Perspective) (crypto.AEAD, error)

// KeyExchangeFunction is used to make a new KEX
type KeyExchangeFunction func() (crypto.KeyExchange, error)

// The CryptoSetupServer handles all things crypto for the Session
type cryptoSetupServer struct {
	mutex sync.RWMutex

	connID               protocol.ConnectionID
	remoteAddr           net.Addr
	scfg                 *ServerConfig
	diversificationNonce []byte

	version           protocol.VersionNumber
	supportedVersions []protocol.VersionNumber

	acceptSTKCallback func(net.Addr, *Cookie) bool

	nullAEAD                    crypto.AEAD
	secureAEAD                  crypto.AEAD
	forwardSecureAEAD           crypto.AEAD
	receivedForwardSecurePacket bool
	receivedSecurePacket        bool
	sentSHLO                    chan struct{} // this channel is closed as soon as the SHLO has been written

	receivedParams bool
	paramsChan     chan<- TransportParameters
	handshakeEvent chan<- struct{}

	keyDerivation QuicCryptoKeyDerivationFunction
	keyExchange   KeyExchangeFunction

	cryptoStream io.ReadWriter

	params *TransportParameters

	sni string // need to fill out the ConnectionState

	logger utils.Logger
}

var _ CryptoSetup = &cryptoSetupServer{}

// ErrNSTPExperiment is returned when the client sends the NSTP tag in the CHLO.
// This is an experiment implemented by Chrome in QUIC 38, which we don't support at this point.
var ErrNSTPExperiment = qerr.Error(qerr.InvalidCryptoMessageParameter, "NSTP experiment. Unsupported")

// NewCryptoSetup creates a new CryptoSetup instance for a server
func NewCryptoSetup(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	remoteAddr net.Addr,
	version protocol.VersionNumber,
	divNonce []byte,
	scfg *ServerConfig,
	params *TransportParameters,
	supportedVersions []protocol.VersionNumber,
	acceptSTK func(net.Addr, *Cookie) bool,
	paramsChan chan<- TransportParameters,
	handshakeEvent chan<- struct{},
	logger utils.Logger,
) (CryptoSetup, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, version)
	if err != nil {
		return nil, err
	}
	return &cryptoSetupServer{
		cryptoStream:         cryptoStream,
		connID:               connID,
		remoteAddr:           remoteAddr,
		version:              version,
		supportedVersions:    supportedVersions,
		diversificationNonce: divNonce,
		scfg:                 scfg,
		keyDerivation:        crypto.DeriveQuicCryptoAESKeys,
		keyExchange:          getEphermalKEX,
		nullAEAD:             nullAEAD,
		params:               params,
		acceptSTKCallback:    acceptSTK,
		sentSHLO:             make(chan struct{}),
		paramsChan:           paramsChan,
		handshakeEvent:       handshakeEvent,
		logger:               logger,
	}, nil
}

// HandleCryptoStream reads and writes messages on the crypto stream
func (h *cryptoSetupServer) HandleCryptoStream() error {
	for {
		var chloData bytes.Buffer
		message, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &chloData))
		if err != nil {
			return qerr.HandshakeFailed
		}
		if message.Tag != TagCHLO {
			return qerr.InvalidCryptoMessageType
		}

		h.logger.Debugf("Got %s", message)
		done, err := h.handleMessage(chloData.Bytes(), message.Data)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (h *cryptoSetupServer) handleMessage(chloData []byte, cryptoData map[Tag][]byte) (bool, error) {
	if _, isNSTPExperiment := cryptoData[TagNSTP]; isNSTPExperiment {
		return false, ErrNSTPExperiment
	}

	sniSlice, ok := cryptoData[TagSNI]
	if !ok {
		return false, qerr.Error(qerr.CryptoMessageParameterNotFound, "SNI required")
	}
	sni := string(sniSlice)
	if sni == "" {
		return false, qerr.Error(qerr.CryptoMessageParameterNotFound, "SNI required")
	}
	h.sni = sni

	// prevent version downgrade attacks
	// see https://groups.google.com/a/chromium.org/forum/#!topic/proto-quic/N-de9j63tCk for a discussion and examples
	verSlice, ok := cryptoData[TagVER]
	if !ok {
		return false, qerr.Error(qerr.InvalidCryptoMessageParameter, "client hello missing version tag")
	}
	if len(verSlice) != 4 {
		return false, qerr.Error(qerr.InvalidCryptoMessageParameter, "incorrect version tag")
	}
	ver := protocol.VersionNumber(binary.BigEndian.Uint32(verSlice))
	// If the client's preferred version is not the version we are currently speaking, then the client went through a version negotiation.  In this case, we need to make sure that we actually do not support this version and that it wasn't a downgrade attack.
	if ver != h.version && protocol.IsSupportedVersion(h.supportedVersions, ver) {
		return false, qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")
	}

	var reply []byte
	var err error

	certUncompressed, err := h.scfg.certChain.GetLeafCert(sni)
	if err != nil {
		return false, err
	}

	params, err := readHelloMap(cryptoData)
	if err != nil {
		return false, err
	}
	// blocks until the session has received the parameters
	if !h.receivedParams {
		h.receivedParams = true
		h.paramsChan <- *params
	}

	if !h.isInchoateCHLO(cryptoData, certUncompressed) {
		// We have a CHLO with a proper server config ID, do a 0-RTT handshake
		reply, err = h.handleCHLO(sni, chloData, cryptoData)
		if err != nil {
			return false, err
		}
		if _, err := h.cryptoStream.Write(reply); err != nil {
			return false, err
		}
		h.handshakeEvent <- struct{}{}
		close(h.sentSHLO)
		return true, nil
	}

	// We have an inchoate or non-matching CHLO, we now send a rejection
	reply, err = h.handleInchoateCHLO(sni, chloData, cryptoData)
	if err != nil {
		return false, err
	}
	_, err = h.cryptoStream.Write(reply)
	return false, err
}

// Open a message
func (h *cryptoSetupServer) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.forwardSecureAEAD != nil {
		res, err := h.forwardSecureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			if !h.receivedForwardSecurePacket { // this is the first forward secure packet we receive from the client
				h.logger.Debugf("Received first forward-secure packet. Stopping to accept all lower encryption levels.")
				h.receivedForwardSecurePacket = true
				// wait for the send on the handshakeEvent chan
				<-h.sentSHLO
				close(h.handshakeEvent)
			}
			return res, protocol.EncryptionForwardSecure, nil
		}
		if h.receivedForwardSecurePacket {
			return nil, protocol.EncryptionUnspecified, err
		}
	}
	if h.secureAEAD != nil {
		res, err := h.secureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			h.logger.Debugf("Received first secure packet. Stopping to accept unencrypted packets.")
			h.receivedSecurePacket = true
			return res, protocol.EncryptionSecure, nil
		}
		if h.receivedSecurePacket {
			return nil, protocol.EncryptionUnspecified, err
		}
	}
	res, err := h.nullAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return res, protocol.EncryptionUnspecified, err
	}
	return res, protocol.EncryptionUnencrypted, err
}

func (h *cryptoSetupServer) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.forwardSecureAEAD != nil {
		return protocol.EncryptionForwardSecure, h.forwardSecureAEAD
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupServer) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.secureAEAD != nil {
		return protocol.EncryptionSecure, h.secureAEAD
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupServer) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionSecure:
		if h.secureAEAD == nil {
			return nil, errors.New("CryptoSetupServer: no secureAEAD")
		}
		return h.secureAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.forwardSecureAEAD == nil {
			return nil, errors.New("CryptoSetupServer: no forwardSecureAEAD")
		}
		return h.forwardSecureAEAD, nil
	}
	return nil, errors.New("CryptoSetupServer: no encryption level specified")
}

func (h *cryptoSetupServer) isInchoateCHLO(cryptoData map[Tag][]byte, cert []byte) bool {
	if _, ok := cryptoData[TagPUBS]; !ok {
		return true
	}
	scid, ok := cryptoData[TagSCID]
	if !ok || !bytes.Equal(h.scfg.ID, scid) {
		return true
	}
	xlctTag, ok := cryptoData[TagXLCT]
	if !ok || len(xlctTag) != 8 {
		return true
	}
	xlct := binary.LittleEndian.Uint64(xlctTag)
	if crypto.HashCert(cert) != xlct {
		return true
	}
	return !h.acceptSTK(cryptoData[TagSTK])
}

func (h *cryptoSetupServer) acceptSTK(token []byte) bool {
	stk, err := h.scfg.cookieGenerator.DecodeToken(token)
	if err != nil {
		h.logger.Debugf("STK invalid: %s", err.Error())
		return false
	}
	return h.acceptSTKCallback(h.remoteAddr, stk)
}

func (h *cryptoSetupServer) handleInchoateCHLO(sni string, chlo []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	token, err := h.scfg.cookieGenerator.NewToken(h.remoteAddr)
	if err != nil {
		return nil, err
	}

	replyMap := map[Tag][]byte{
		TagSCFG: h.scfg.Get(),
		TagSTK:  token,
		TagSVID: []byte("quic-go"),
	}

	if h.acceptSTK(cryptoData[TagSTK]) {
		proof, err := h.scfg.Sign(sni, chlo)
		if err != nil {
			return nil, err
		}

		commonSetHashes := cryptoData[TagCCS]
		cachedCertsHashes := cryptoData[TagCCRT]

		certCompressed, err := h.scfg.GetCertsCompressed(sni, commonSetHashes, cachedCertsHashes)
		if err != nil {
			return nil, err
		}
		// Token was valid, send more details
		replyMap[TagPROF] = proof
		replyMap[TagCERT] = certCompressed
	}

	message := HandshakeMessage{
		Tag:  TagREJ,
		Data: replyMap,
	}

	var serverReply bytes.Buffer
	message.Write(&serverReply)
	h.logger.Debugf("Sending %s", message)
	return serverReply.Bytes(), nil
}

func (h *cryptoSetupServer) handleCHLO(sni string, data []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	// We have a CHLO matching our server config, we can continue with the 0-RTT handshake
	sharedSecret, err := h.scfg.kex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	certUncompressed, err := h.scfg.certChain.GetLeafCert(sni)
	if err != nil {
		return nil, err
	}

	serverNonce := make([]byte, 32)
	if _, err = rand.Read(serverNonce); err != nil {
		return nil, err
	}

	clientNonce := cryptoData[TagNONC]
	err = h.validateClientNonce(clientNonce)
	if err != nil {
		return nil, err
	}

	aead := cryptoData[TagAEAD]
	if !bytes.Equal(aead, []byte("AESG")) {
		return nil, qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")
	}

	kexs := cryptoData[TagKEXS]
	if !bytes.Equal(kexs, []byte("C255")) {
		return nil, qerr.Error(qerr.CryptoNoSupport, "Unsupported AEAD or KEXS")
	}

	h.secureAEAD, err = h.keyDerivation(
		false,
		sharedSecret,
		clientNonce,
		h.connID,
		data,
		h.scfg.Get(),
		certUncompressed,
		h.diversificationNonce,
		protocol.PerspectiveServer,
	)
	if err != nil {
		return nil, err
	}
	h.logger.Debugf("Creating AEAD for secure encryption.")
	h.handshakeEvent <- struct{}{}

	// Generate a new curve instance to derive the forward secure key
	var fsNonce bytes.Buffer
	fsNonce.Write(clientNonce)
	fsNonce.Write(serverNonce)
	ephermalKex, err := h.keyExchange()
	if err != nil {
		return nil, err
	}
	ephermalSharedSecret, err := ephermalKex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}

	h.forwardSecureAEAD, err = h.keyDerivation(
		true,
		ephermalSharedSecret,
		fsNonce.Bytes(),
		h.connID,
		data,
		h.scfg.Get(),
		certUncompressed,
		nil,
		protocol.PerspectiveServer,
	)
	if err != nil {
		return nil, err
	}
	h.logger.Debugf("Creating AEAD for forward-secure encryption.")

	replyMap := h.params.getHelloMap()
	// add crypto parameters
	verTag := &bytes.Buffer{}
	for _, v := range h.supportedVersions {
		utils.BigEndian.WriteUint32(verTag, uint32(v))
	}
	replyMap[TagPUBS] = ephermalKex.PublicKey()
	replyMap[TagSNO] = serverNonce
	replyMap[TagVER] = verTag.Bytes()

	// note that the SHLO *has* to fit into one packet
	message := HandshakeMessage{
		Tag:  TagSHLO,
		Data: replyMap,
	}
	var reply bytes.Buffer
	message.Write(&reply)
	h.logger.Debugf("Sending %s", message)
	return reply.Bytes(), nil
}

func (h *cryptoSetupServer) ConnectionState() ConnectionState {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return ConnectionState{
		ServerName:        h.sni,
		HandshakeComplete: h.receivedForwardSecurePacket,
	}
}

func (h *cryptoSetupServer) validateClientNonce(nonce []byte) error {
	if len(nonce) != 32 {
		return qerr.Error(qerr.InvalidCryptoMessageParameter, "invalid client nonce length")
	}
	if !bytes.Equal(nonce[4:12], h.scfg.obit) {
		return qerr.Error(qerr.InvalidCryptoMessageParameter, "OBIT not matching")
	}
	return nil
}
