package handshake

import (
	"errors"
	"fmt"
	"math"

	"github.com/lucas-clemente/quic-go/qerr"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type extensionHandlerClient struct {
	ourParams  *TransportParameters
	paramsChan chan TransportParameters

	initialVersion    protocol.VersionNumber
	supportedVersions []protocol.VersionNumber
	version           protocol.VersionNumber
}

var _ mint.AppExtensionHandler = &extensionHandlerClient{}
var _ TLSExtensionHandler = &extensionHandlerClient{}

// NewExtensionHandlerClient creates a new extension handler for the client.
func NewExtensionHandlerClient(
	params *TransportParameters,
	initialVersion protocol.VersionNumber,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) TLSExtensionHandler {
	paramsChan := make(chan TransportParameters, 1)
	return &extensionHandlerClient{
		ourParams:         params,
		paramsChan:        paramsChan,
		initialVersion:    initialVersion,
		supportedVersions: supportedVersions,
		version:           version,
	}
}

func (h *extensionHandlerClient) Send(hType mint.HandshakeType, el *mint.ExtensionList) error {
	if hType != mint.HandshakeTypeClientHello {
		return nil
	}

	data, err := syntax.Marshal(clientHelloTransportParameters{
		InitialVersion: uint32(h.initialVersion),
		Parameters:     h.ourParams.getTransportParameters(),
	})
	if err != nil {
		return err
	}
	return el.Add(&tlsExtensionBody{data})
}

func (h *extensionHandlerClient) Receive(hType mint.HandshakeType, el *mint.ExtensionList) error {
	ext := &tlsExtensionBody{}
	found, err := el.Find(ext)
	if err != nil {
		return err
	}

	if hType != mint.HandshakeTypeEncryptedExtensions && hType != mint.HandshakeTypeNewSessionTicket {
		if found {
			return fmt.Errorf("Unexpected QUIC extension in handshake message %d", hType)
		}
		return nil
	}
	if hType == mint.HandshakeTypeNewSessionTicket {
		// the extension it's optional in the NewSessionTicket message
		// TODO: handle this
		return nil
	}

	// hType == mint.HandshakeTypeEncryptedExtensions
	if !found {
		return errors.New("EncryptedExtensions message didn't contain a QUIC extension")
	}

	eetp := &encryptedExtensionsTransportParameters{}
	if _, err := syntax.Unmarshal(ext.data, eetp); err != nil {
		return err
	}
	serverSupportedVersions := make([]protocol.VersionNumber, len(eetp.SupportedVersions))
	for i, v := range eetp.SupportedVersions {
		serverSupportedVersions[i] = protocol.VersionNumber(v)
	}
	// check that the negotiated_version is the current version
	if protocol.VersionNumber(eetp.NegotiatedVersion) != h.version {
		return qerr.Error(qerr.VersionNegotiationMismatch, "current version doesn't match negotiated_version")
	}
	// check that the current version is included in the supported versions
	if !protocol.IsSupportedVersion(serverSupportedVersions, h.version) {
		return qerr.Error(qerr.VersionNegotiationMismatch, "current version not included in the supported versions")
	}
	// if version negotiation was performed, check that we would have selected the current version based on the supported versions sent by the server
	if h.version != h.initialVersion {
		negotiatedVersion, ok := protocol.ChooseSupportedVersion(h.supportedVersions, serverSupportedVersions)
		if !ok || h.version != negotiatedVersion {
			return qerr.Error(qerr.VersionNegotiationMismatch, "would have picked a different version")
		}
	}

	// check that the server sent the stateless reset token
	var foundStatelessResetToken bool
	for _, p := range eetp.Parameters {
		if p.Parameter == statelessResetTokenParameterID {
			if len(p.Value) != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", len(p.Value))
			}
			foundStatelessResetToken = true
			// TODO: handle this value
		}
	}
	if !foundStatelessResetToken {
		// TODO: return the right error here
		return errors.New("server didn't sent stateless_reset_token")
	}
	params, err := readTransportParamters(eetp.Parameters)
	if err != nil {
		return err
	}
	// TODO(#878): remove this when implementing the MAX_STREAM_ID frame
	params.MaxStreams = math.MaxUint32
	h.paramsChan <- *params
	return nil
}

func (h *extensionHandlerClient) GetPeerParams() <-chan TransportParameters {
	return h.paramsChan
}
