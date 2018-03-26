package mint

import (
	"crypto/x509"
	"time"
)

// Marker interface for actions that an implementation should take based on
// state transitions.
type HandshakeAction interface{}

type QueueHandshakeMessage struct {
	Message *HandshakeMessage
}

type SendQueuedHandshake struct{}

type SendEarlyData struct{}

type ReadEarlyData struct{}

type ReadPastEarlyData struct{}

type RekeyIn struct {
	epoch  Epoch
	KeySet keySet
}

type RekeyOut struct {
	epoch  Epoch
	KeySet keySet
}

type StorePSK struct {
	PSK PreSharedKey
}

type HandshakeState interface {
	Next(handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert)
	State() State
}

type AppExtensionHandler interface {
	Send(hs HandshakeType, el *ExtensionList) error
	Receive(hs HandshakeType, el *ExtensionList) error
}

// ConnectionOptions objects represent per-connection settings for a client
// initiating a connection
type ConnectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

// ConnectionParameters objects represent the parameters negotiated for a
// connection.
type ConnectionParameters struct {
	UsingPSK               bool
	UsingDH                bool
	ClientSendingEarlyData bool
	UsingEarlyData         bool
	UsingClientAuth        bool

	CipherSuite CipherSuite
	ServerName  string
	NextProto   string
}

// Working state for the handshake.
type HandshakeContext struct {
	hIn, hOut *HandshakeLayer
}

func (hc *HandshakeContext) SetVersion(version uint16) {
	if hc.hIn.conn != nil {
		hc.hIn.conn.SetVersion(version)
	}
	if hc.hOut.conn != nil {
		hc.hOut.conn.SetVersion(version)
	}
}

// stateConnected is symmetric between client and server
type stateConnected struct {
	Params              ConnectionParameters
	hsCtx               HandshakeContext
	isClient            bool
	cryptoParams        CipherSuiteParams
	resumptionSecret    []byte
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte
	peerCertificates    []*x509.Certificate
	verifiedChains      [][]*x509.Certificate
}

var _ HandshakeState = &stateConnected{}

func (state stateConnected) State() State {
	if state.isClient {
		return StateClientConnected
	}
	return StateServerConnected
}

func (state *stateConnected) KeyUpdate(request KeyUpdateRequest) ([]HandshakeAction, Alert) {
	var trafficKeys keySet
	if state.isClient {
		state.clientTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.clientTrafficSecret,
			labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
	} else {
		state.serverTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.serverTrafficSecret,
			labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
	}

	kum, err := state.hsCtx.hOut.HandshakeMessageFromBody(&KeyUpdateBody{KeyUpdateRequest: request})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling key update message: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		QueueHandshakeMessage{kum},
		SendQueuedHandshake{},
		RekeyOut{epoch: EpochUpdate, KeySet: trafficKeys},
	}
	return toSend, AlertNoAlert
}

func (state *stateConnected) NewSessionTicket(length int, lifetime, earlyDataLifetime uint32) ([]HandshakeAction, Alert) {
	tkt, err := NewSessionTicket(length, lifetime)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error generating NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	err = tkt.Extensions.Add(&TicketEarlyDataInfoExtension{earlyDataLifetime})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error adding extension to NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	resumptionKey := HkdfExpandLabel(state.cryptoParams.Hash, state.resumptionSecret,
		labelResumption, tkt.TicketNonce, state.cryptoParams.Hash.Size())

	newPSK := PreSharedKey{
		CipherSuite:  state.cryptoParams.Suite,
		IsResumption: true,
		Identity:     tkt.Ticket,
		Key:          resumptionKey,
		NextProto:    state.Params.NextProto,
		ReceivedAt:   time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(tkt.TicketLifetime) * time.Second),
		TicketAgeAdd: tkt.TicketAgeAdd,
	}

	tktm, err := state.hsCtx.hOut.HandshakeMessageFromBody(tkt)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		StorePSK{newPSK},
		QueueHandshakeMessage{tktm},
		SendQueuedHandshake{},
	}
	return toSend, AlertNoAlert
}

// Next does nothing for this state.
func (state stateConnected) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	return state, nil, AlertNoAlert
}

func (state stateConnected) ProcessMessage(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[StateConnected] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	switch body := bodyGeneric.(type) {
	case *KeyUpdateBody:
		var trafficKeys keySet
		if !state.isClient {
			state.clientTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.clientTrafficSecret,
				labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		} else {
			state.serverTrafficSecret = HkdfExpandLabel(state.cryptoParams.Hash, state.serverTrafficSecret,
				labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.Hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		}

		toSend := []HandshakeAction{RekeyIn{epoch: EpochUpdate, KeySet: trafficKeys}}

		// If requested, roll outbound keys and send a KeyUpdate
		if body.KeyUpdateRequest == KeyUpdateRequested {
			logf(logTypeHandshake, "Received key update, update requested", body.KeyUpdateRequest)
			moreToSend, alert := state.KeyUpdate(KeyUpdateNotRequested)
			if alert != AlertNoAlert {
				return nil, nil, alert
			}
			toSend = append(toSend, moreToSend...)
		}
		return state, toSend, AlertNoAlert
	case *NewSessionTicketBody:
		// XXX: Allow NewSessionTicket in both directions?
		if !state.isClient {
			return nil, nil, AlertUnexpectedMessage
		}

		resumptionKey := HkdfExpandLabel(state.cryptoParams.Hash, state.resumptionSecret,
			labelResumption, body.TicketNonce, state.cryptoParams.Hash.Size())
		psk := PreSharedKey{
			CipherSuite:  state.cryptoParams.Suite,
			IsResumption: true,
			Identity:     body.Ticket,
			Key:          resumptionKey,
			NextProto:    state.Params.NextProto,
			ReceivedAt:   time.Now(),
			ExpiresAt:    time.Now().Add(time.Duration(body.TicketLifetime) * time.Second),
			TicketAgeAdd: body.TicketAgeAdd,
		}

		toSend := []HandshakeAction{StorePSK{psk}}
		return state, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[StateConnected] Unexpected message type %v", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}
