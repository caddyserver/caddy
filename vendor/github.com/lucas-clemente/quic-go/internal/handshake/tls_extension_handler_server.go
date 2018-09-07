package handshake

import (
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type extensionHandlerServer struct {
	ourParams  *TransportParameters
	paramsChan chan TransportParameters

	version           protocol.VersionNumber
	supportedVersions []protocol.VersionNumber

	logger utils.Logger
}

var _ mint.AppExtensionHandler = &extensionHandlerServer{}
var _ TLSExtensionHandler = &extensionHandlerServer{}

// NewExtensionHandlerServer creates a new extension handler for the server
func NewExtensionHandlerServer(
	params *TransportParameters,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
	logger utils.Logger,
) TLSExtensionHandler {
	// Processing the ClientHello is performed statelessly (and from a single go-routine).
	// Therefore, we have to use a buffered chan to pass the transport parameters to that go routine.
	paramsChan := make(chan TransportParameters, 1)
	return &extensionHandlerServer{
		ourParams:         params,
		paramsChan:        paramsChan,
		supportedVersions: supportedVersions,
		version:           version,
		logger:            logger,
	}
}

func (h *extensionHandlerServer) Send(hType mint.HandshakeType, el *mint.ExtensionList) error {
	if hType != mint.HandshakeTypeEncryptedExtensions {
		return nil
	}
	h.logger.Debugf("Sending Transport Parameters: %s", h.ourParams)
	eetp := &encryptedExtensionsTransportParameters{
		NegotiatedVersion: h.version,
		SupportedVersions: protocol.GetGreasedVersions(h.supportedVersions),
		Parameters:        *h.ourParams,
	}
	return el.Add(&tlsExtensionBody{data: eetp.Marshal()})
}

func (h *extensionHandlerServer) Receive(hType mint.HandshakeType, el *mint.ExtensionList) error {
	ext := &tlsExtensionBody{}
	found, err := el.Find(ext)
	if err != nil {
		return err
	}

	if hType != mint.HandshakeTypeClientHello {
		if found {
			return fmt.Errorf("Unexpected QUIC extension in handshake message %d", hType)
		}
		return nil
	}

	if !found {
		return errors.New("ClientHello didn't contain a QUIC extension")
	}
	chtp := &clientHelloTransportParameters{}
	if err := chtp.Unmarshal(ext.data); err != nil {
		return err
	}

	// perform the stateless version negotiation validation:
	// make sure that we would have sent a Version Negotiation Packet if the client offered the initial version
	// this is the case if and only if the initial version is not contained in the supported versions
	if chtp.InitialVersion != h.version && protocol.IsSupportedVersion(h.supportedVersions, chtp.InitialVersion) {
		return qerr.Error(qerr.VersionNegotiationMismatch, "Client should have used the initial version")
	}

	// check that the client didn't send a stateless reset token
	if len(chtp.Parameters.StatelessResetToken) != 0 {
		// TODO: return the correct error type
		return errors.New("client sent a stateless reset token")
	}
	h.logger.Debugf("Received Transport Parameters: %s", &chtp.Parameters)
	h.paramsChan <- chtp.Parameters
	return nil
}

func (h *extensionHandlerServer) GetPeerParams() <-chan TransportParameters {
	return h.paramsChan
}
