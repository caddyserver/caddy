package handshake

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
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

	transportParams := append(
		h.ourParams.getTransportParameters(),
		// TODO(#855): generate a real token
		transportParameter{statelessResetTokenParameterID, bytes.Repeat([]byte{42}, 16)},
	)
	supportedVersions := protocol.GetGreasedVersions(h.supportedVersions)
	versions := make([]uint32, len(supportedVersions))
	for i, v := range supportedVersions {
		versions[i] = uint32(v)
	}
	h.logger.Debugf("Sending Transport Parameters: %s", h.ourParams)
	data, err := syntax.Marshal(encryptedExtensionsTransportParameters{
		NegotiatedVersion: uint32(h.version),
		SupportedVersions: versions,
		Parameters:        transportParams,
	})
	if err != nil {
		return err
	}
	return el.Add(&tlsExtensionBody{data})
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
	if _, err := syntax.Unmarshal(ext.data, chtp); err != nil {
		return err
	}
	initialVersion := protocol.VersionNumber(chtp.InitialVersion)

	// perform the stateless version negotiation validation:
	// make sure that we would have sent a Version Negotiation Packet if the client offered the initial version
	// this is the case if and only if the initial version is not contained in the supported versions
	if initialVersion != h.version && protocol.IsSupportedVersion(h.supportedVersions, initialVersion) {
		return qerr.Error(qerr.VersionNegotiationMismatch, "Client should have used the initial version")
	}

	for _, p := range chtp.Parameters {
		if p.Parameter == statelessResetTokenParameterID {
			// TODO: return the correct error type
			return errors.New("client sent a stateless reset token")
		}
	}
	params, err := readTransportParameters(chtp.Parameters)
	if err != nil {
		return err
	}
	h.logger.Debugf("Received Transport Parameters: %s", params)
	h.paramsChan <- *params
	return nil
}

func (h *extensionHandlerServer) GetPeerParams() <-chan TransportParameters {
	return h.paramsChan
}
