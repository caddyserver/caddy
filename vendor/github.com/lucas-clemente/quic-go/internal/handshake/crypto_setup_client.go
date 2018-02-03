package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

type cryptoSetupClient struct {
	mutex sync.RWMutex

	hostname           string
	connID             protocol.ConnectionID
	version            protocol.VersionNumber
	initialVersion     protocol.VersionNumber
	negotiatedVersions []protocol.VersionNumber

	cryptoStream io.ReadWriter

	serverConfig *serverConfigClient

	stk              []byte
	sno              []byte
	nonc             []byte
	proof            []byte
	chloForSignature []byte
	lastSentCHLO     []byte
	certManager      crypto.CertManager

	divNonceChan         chan []byte
	diversificationNonce []byte

	clientHelloCounter int
	serverVerified     bool // has the certificate chain and the proof already been verified
	keyDerivation      QuicCryptoKeyDerivationFunction
	keyExchange        KeyExchangeFunction

	receivedSecurePacket bool
	nullAEAD             crypto.AEAD
	secureAEAD           crypto.AEAD
	forwardSecureAEAD    crypto.AEAD

	paramsChan     chan<- TransportParameters
	handshakeEvent chan<- struct{}

	params *TransportParameters
}

var _ CryptoSetup = &cryptoSetupClient{}

var (
	errNoObitForClientNonce             = errors.New("CryptoSetup BUG: No OBIT for client nonce available")
	errClientNonceAlreadyExists         = errors.New("CryptoSetup BUG: A client nonce was already generated")
	errConflictingDiversificationNonces = errors.New("Received two different diversification nonces")
)

// NewCryptoSetupClient creates a new CryptoSetup instance for a client
func NewCryptoSetupClient(
	cryptoStream io.ReadWriter,
	hostname string,
	connID protocol.ConnectionID,
	version protocol.VersionNumber,
	tlsConfig *tls.Config,
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	handshakeEvent chan<- struct{},
	initialVersion protocol.VersionNumber,
	negotiatedVersions []protocol.VersionNumber,
) (CryptoSetup, error) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}
	return &cryptoSetupClient{
		cryptoStream:       cryptoStream,
		hostname:           hostname,
		connID:             connID,
		version:            version,
		certManager:        crypto.NewCertManager(tlsConfig),
		params:             params,
		keyDerivation:      crypto.DeriveQuicCryptoAESKeys,
		keyExchange:        getEphermalKEX,
		nullAEAD:           nullAEAD,
		paramsChan:         paramsChan,
		handshakeEvent:     handshakeEvent,
		initialVersion:     initialVersion,
		negotiatedVersions: negotiatedVersions,
		divNonceChan:       make(chan []byte),
	}, nil
}

func (h *cryptoSetupClient) HandleCryptoStream() error {
	messageChan := make(chan HandshakeMessage)
	errorChan := make(chan error, 1)

	go func() {
		for {
			message, err := ParseHandshakeMessage(h.cryptoStream)
			if err != nil {
				errorChan <- qerr.Error(qerr.HandshakeFailed, err.Error())
				return
			}
			messageChan <- message
		}
	}()

	for {
		err := h.maybeUpgradeCrypto()
		if err != nil {
			return err
		}

		h.mutex.RLock()
		sendCHLO := h.secureAEAD == nil
		h.mutex.RUnlock()

		if sendCHLO {
			err = h.sendCHLO()
			if err != nil {
				return err
			}
		}

		var message HandshakeMessage
		select {
		case divNonce := <-h.divNonceChan:
			if len(h.diversificationNonce) != 0 && !bytes.Equal(h.diversificationNonce, divNonce) {
				return errConflictingDiversificationNonces
			}
			h.diversificationNonce = divNonce
			// there's no message to process, but we should try upgrading the crypto again
			continue
		case message = <-messageChan:
		case err = <-errorChan:
			return err
		}

		utils.Debugf("Got %s", message)
		switch message.Tag {
		case TagREJ:
			if err := h.handleREJMessage(message.Data); err != nil {
				return err
			}
		case TagSHLO:
			params, err := h.handleSHLOMessage(message.Data)
			if err != nil {
				return err
			}
			// blocks until the session has received the parameters
			h.paramsChan <- *params
			h.handshakeEvent <- struct{}{}
			close(h.handshakeEvent)
		default:
			return qerr.InvalidCryptoMessageType
		}
	}
}

func (h *cryptoSetupClient) handleREJMessage(cryptoData map[Tag][]byte) error {
	var err error

	if stk, ok := cryptoData[TagSTK]; ok {
		h.stk = stk
	}

	if sno, ok := cryptoData[TagSNO]; ok {
		h.sno = sno
	}

	// TODO: what happens if the server sends a different server config in two packets?
	if scfg, ok := cryptoData[TagSCFG]; ok {
		h.serverConfig, err = parseServerConfig(scfg)
		if err != nil {
			return err
		}

		if h.serverConfig.IsExpired() {
			return qerr.CryptoServerConfigExpired
		}

		// now that we have a server config, we can use its OBIT value to generate a client nonce
		if len(h.nonc) == 0 {
			err = h.generateClientNonce()
			if err != nil {
				return err
			}
		}
	}

	if proof, ok := cryptoData[TagPROF]; ok {
		h.proof = proof
		h.chloForSignature = h.lastSentCHLO
	}

	if crt, ok := cryptoData[TagCERT]; ok {
		err := h.certManager.SetData(crt)
		if err != nil {
			return qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")
		}

		err = h.certManager.Verify(h.hostname)
		if err != nil {
			utils.Infof("Certificate validation failed: %s", err.Error())
			return qerr.ProofInvalid
		}
	}

	if h.serverConfig != nil && len(h.proof) != 0 && h.certManager.GetLeafCert() != nil {
		validProof := h.certManager.VerifyServerProof(h.proof, h.chloForSignature, h.serverConfig.Get())
		if !validProof {
			utils.Infof("Server proof verification failed")
			return qerr.ProofInvalid
		}

		h.serverVerified = true
	}

	return nil
}

func (h *cryptoSetupClient) handleSHLOMessage(cryptoData map[Tag][]byte) (*TransportParameters, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.receivedSecurePacket {
		return nil, qerr.Error(qerr.CryptoEncryptionLevelIncorrect, "unencrypted SHLO message")
	}

	if sno, ok := cryptoData[TagSNO]; ok {
		h.sno = sno
	}

	serverPubs, ok := cryptoData[TagPUBS]
	if !ok {
		return nil, qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")
	}

	verTag, ok := cryptoData[TagVER]
	if !ok {
		return nil, qerr.Error(qerr.InvalidCryptoMessageParameter, "server hello missing version list")
	}
	if !h.validateVersionList(verTag) {
		return nil, qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")
	}

	nonce := append(h.nonc, h.sno...)

	ephermalSharedSecret, err := h.serverConfig.kex.CalculateSharedKey(serverPubs)
	if err != nil {
		return nil, err
	}

	leafCert := h.certManager.GetLeafCert()

	h.forwardSecureAEAD, err = h.keyDerivation(
		true,
		ephermalSharedSecret,
		nonce,
		h.connID,
		h.lastSentCHLO,
		h.serverConfig.Get(),
		leafCert,
		nil,
		protocol.PerspectiveClient,
	)
	if err != nil {
		return nil, err
	}

	params, err := readHelloMap(cryptoData)
	if err != nil {
		return nil, qerr.InvalidCryptoMessageParameter
	}
	return params, nil
}

func (h *cryptoSetupClient) validateVersionList(verTags []byte) bool {
	numNegotiatedVersions := len(h.negotiatedVersions)
	if numNegotiatedVersions == 0 {
		return true
	}
	if len(verTags)%4 != 0 || len(verTags)/4 != numNegotiatedVersions {
		return false
	}

	b := bytes.NewReader(verTags)
	for i := 0; i < numNegotiatedVersions; i++ {
		v, err := utils.BigEndian.ReadUint32(b)
		if err != nil { // should never occur, since the length was already checked
			return false
		}
		if protocol.VersionNumber(v) != h.negotiatedVersions[i] {
			return false
		}
	}
	return true
}

func (h *cryptoSetupClient) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.forwardSecureAEAD != nil {
		data, err := h.forwardSecureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			return data, protocol.EncryptionForwardSecure, nil
		}
		return nil, protocol.EncryptionUnspecified, err
	}

	if h.secureAEAD != nil {
		data, err := h.secureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			h.receivedSecurePacket = true
			return data, protocol.EncryptionSecure, nil
		}
		if h.receivedSecurePacket {
			return nil, protocol.EncryptionUnspecified, err
		}
	}
	res, err := h.nullAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return nil, protocol.EncryptionUnspecified, err
	}
	return res, protocol.EncryptionUnencrypted, nil
}

func (h *cryptoSetupClient) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.forwardSecureAEAD != nil {
		return protocol.EncryptionForwardSecure, h.forwardSecureAEAD
	} else if h.secureAEAD != nil {
		return protocol.EncryptionSecure, h.secureAEAD
	} else {
		return protocol.EncryptionUnencrypted, h.nullAEAD
	}
}

func (h *cryptoSetupClient) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupClient) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionSecure:
		if h.secureAEAD == nil {
			return nil, errors.New("CryptoSetupClient: no secureAEAD")
		}
		return h.secureAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.forwardSecureAEAD == nil {
			return nil, errors.New("CryptoSetupClient: no forwardSecureAEAD")
		}
		return h.forwardSecureAEAD, nil
	}
	return nil, errors.New("CryptoSetupClient: no encryption level specified")
}

func (h *cryptoSetupClient) DiversificationNonce() []byte {
	panic("not needed for cryptoSetupClient")
}

func (h *cryptoSetupClient) SetDiversificationNonce(data []byte) {
	h.divNonceChan <- data
}

func (h *cryptoSetupClient) ConnectionState() ConnectionState {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return ConnectionState{
		HandshakeComplete: h.forwardSecureAEAD != nil,
		PeerCertificates:  h.certManager.GetChain(),
	}
}

func (h *cryptoSetupClient) sendCHLO() error {
	h.clientHelloCounter++
	if h.clientHelloCounter > protocol.MaxClientHellos {
		return qerr.Error(qerr.CryptoTooManyRejects, fmt.Sprintf("More than %d rejects", protocol.MaxClientHellos))
	}

	b := &bytes.Buffer{}

	tags, err := h.getTags()
	if err != nil {
		return err
	}
	h.addPadding(tags)
	message := HandshakeMessage{
		Tag:  TagCHLO,
		Data: tags,
	}

	utils.Debugf("Sending %s", message)
	message.Write(b)

	_, err = h.cryptoStream.Write(b.Bytes())
	if err != nil {
		return err
	}

	h.lastSentCHLO = b.Bytes()
	return nil
}

func (h *cryptoSetupClient) getTags() (map[Tag][]byte, error) {
	tags := h.params.getHelloMap()
	tags[TagSNI] = []byte(h.hostname)
	tags[TagPDMD] = []byte("X509")

	ccs := h.certManager.GetCommonCertificateHashes()
	if len(ccs) > 0 {
		tags[TagCCS] = ccs
	}

	versionTag := make([]byte, 4)
	binary.BigEndian.PutUint32(versionTag, uint32(h.initialVersion))
	tags[TagVER] = versionTag

	if len(h.stk) > 0 {
		tags[TagSTK] = h.stk
	}
	if len(h.sno) > 0 {
		tags[TagSNO] = h.sno
	}

	if h.serverConfig != nil {
		tags[TagSCID] = h.serverConfig.ID

		leafCert := h.certManager.GetLeafCert()
		if leafCert != nil {
			certHash, _ := h.certManager.GetLeafCertHash()
			xlct := make([]byte, 8)
			binary.LittleEndian.PutUint64(xlct, certHash)

			tags[TagNONC] = h.nonc
			tags[TagXLCT] = xlct
			tags[TagKEXS] = []byte("C255")
			tags[TagAEAD] = []byte("AESG")
			tags[TagPUBS] = h.serverConfig.kex.PublicKey() // TODO: check if 3 bytes need to be prepended
		}
	}

	return tags, nil
}

// add a TagPAD to a tagMap, such that the total size will be bigger than the ClientHelloMinimumSize
func (h *cryptoSetupClient) addPadding(tags map[Tag][]byte) {
	var size int
	for _, tag := range tags {
		size += 8 + len(tag) // 4 bytes for the tag + 4 bytes for the offset + the length of the data
	}
	paddingSize := protocol.MinClientHelloSize - size
	if paddingSize > 0 {
		tags[TagPAD] = bytes.Repeat([]byte{0}, paddingSize)
	}
}

func (h *cryptoSetupClient) maybeUpgradeCrypto() error {
	if !h.serverVerified {
		return nil
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	leafCert := h.certManager.GetLeafCert()
	if h.secureAEAD == nil && (h.serverConfig != nil && len(h.serverConfig.sharedSecret) > 0 && len(h.nonc) > 0 && len(leafCert) > 0 && len(h.diversificationNonce) > 0 && len(h.lastSentCHLO) > 0) {
		var err error
		var nonce []byte
		if h.sno == nil {
			nonce = h.nonc
		} else {
			nonce = append(h.nonc, h.sno...)
		}

		h.secureAEAD, err = h.keyDerivation(
			false,
			h.serverConfig.sharedSecret,
			nonce,
			h.connID,
			h.lastSentCHLO,
			h.serverConfig.Get(),
			leafCert,
			h.diversificationNonce,
			protocol.PerspectiveClient,
		)
		if err != nil {
			return err
		}
		h.handshakeEvent <- struct{}{}
	}
	return nil
}

func (h *cryptoSetupClient) generateClientNonce() error {
	if len(h.nonc) > 0 {
		return errClientNonceAlreadyExists
	}

	nonc := make([]byte, 32)
	binary.BigEndian.PutUint32(nonc, uint32(time.Now().Unix()))

	if len(h.serverConfig.obit) != 8 {
		return errNoObitForClientNonce
	}

	copy(nonc[4:12], h.serverConfig.obit)

	_, err := rand.Read(nonc[12:])
	if err != nil {
		return err
	}

	h.nonc = nonc
	return nil
}
