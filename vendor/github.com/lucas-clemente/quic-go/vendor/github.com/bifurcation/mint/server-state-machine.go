package mint

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"hash"
	"reflect"

	"github.com/bifurcation/mint/syntax"
)

// Server State Machine
//
//                              START <-----+
//               Recv ClientHello |         | Send HelloRetryRequest
//                                v         |
//                             RECVD_CH ----+
//                                | Select parameters
//                                | Send ServerHello
//                                v
//                             NEGOTIATED
//                                | Send EncryptedExtensions
//                                | [Send CertificateRequest]
// Can send                       | [Send Certificate + CertificateVerify]
// app data -->                   | Send Finished
// after here                     |
//                    +-----------+--------+
//                    |           |        |
//     Rejected 0-RTT |        No |        | 0-RTT
//                    |     0-RTT |        |
//                    |           |        v
//          +---->READ_PAST       |    WAIT_EOED <---+
//  Decrypt |     |   | Decrypt   |   Recv |   |     | Recv
//    error |     |   | OK + HS   |   EOED |   |     | early data
//          +-----+   |           V        |   +-----+
//                    +---> WAIT_FLIGHT2 <-+
//                                |
//                       +--------+--------+
//               No auth |                 | Client auth
//                       |                 |
//                       |                 v
//                       |             WAIT_CERT
//                       |        Recv |       | Recv Certificate
//                       |       empty |       v
//                       | Certificate |    WAIT_CV
//                       |             |       | Recv
//                       |             v       | CertificateVerify
//                       +-> WAIT_FINISHED <---+
//                                | Recv Finished
//                                v
//                            CONNECTED
//
// NB: Not using state RECVD_CH
//
//  State          Instructions
//  START          {}
//  NEGOTIATED     Send(SH); [RekeyIn;] RekeyOut; Send(EE); [Send(CertReq);] [Send(Cert); Send(CV)]
//  WAIT_EOED      RekeyIn;
//  READ_PAST      {}
//  WAIT_FLIGHT2   {}
//  WAIT_CERT_CR   {}
//  WAIT_CERT      {}
//  WAIT_CV        {}
//  WAIT_FINISHED  RekeyIn; RekeyOut;
//  CONNECTED      StoreTicket || (RekeyIn; [RekeyOut])

// A cookie can be sent to the client in a HRR.
type cookie struct {
	// The CipherSuite that was selected when the client sent the first ClientHello
	CipherSuite     CipherSuite
	ClientHelloHash []byte `tls:"head=2"`

	// The ApplicationCookie can be provided by the application (by setting a Config.CookieHandler)
	ApplicationCookie []byte `tls:"head=2"`
}

type serverStateStart struct {
	Config *Config
	conn   *Conn
	hsCtx  *HandshakeContext
}

var _ HandshakeState = &serverStateStart{}

func (state serverStateStart) State() State {
	return StateServerStart
}

func (state serverStateStart) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeClientHello {
		logf(logTypeHandshake, "[ServerStateStart] unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ch := &ClientHelloBody{LegacyVersion: wireVersion(state.hsCtx.hIn)}
	if err := safeUnmarshal(ch, hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	// We are strict about these things because we only support 1.3
	if ch.LegacyVersion != wireVersion(state.hsCtx.hIn) {
		logf(logTypeHandshake, "[ServerStateStart] Invalid version number: %v", ch.LegacyVersion)
		return nil, nil, AlertDecodeError
	}

	clientHello := hm
	connParams := ConnectionParameters{}

	supportedVersions := &SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello}
	serverName := new(ServerNameExtension)
	supportedGroups := new(SupportedGroupsExtension)
	signatureAlgorithms := new(SignatureAlgorithmsExtension)
	clientKeyShares := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	clientPSK := &PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	clientEarlyData := &EarlyDataExtension{}
	clientALPN := new(ALPNExtension)
	clientPSKModes := new(PSKKeyExchangeModesExtension)
	clientCookie := new(CookieExtension)

	// Handle external extensions.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Receive(HandshakeTypeClientHello, &ch.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error running external extension handler [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	foundExts, err := ch.Extensions.Parse(
		[]ExtensionBody{
			supportedVersions,
			serverName,
			supportedGroups,
			signatureAlgorithms,
			clientEarlyData,
			clientKeyShares,
			clientPSK,
			clientALPN,
			clientPSKModes,
			clientCookie,
		})

	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error parsing extensions [%v]", err)
		return nil, nil, AlertDecodeError
	}

	clientSentCookie := len(clientCookie.Cookie) > 0

	if foundExts[ExtensionTypeServerName] {
		connParams.ServerName = string(*serverName)
	}

	// If the client didn't send supportedVersions or doesn't support 1.3,
	// then we're done here.
	if !foundExts[ExtensionTypeSupportedVersions] {
		logf(logTypeHandshake, "[ServerStateStart] Client did not send supported_versions")
		return nil, nil, AlertProtocolVersion
	}
	versionOK, _ := VersionNegotiation(supportedVersions.Versions, []uint16{supportedVersion})
	if !versionOK {
		logf(logTypeHandshake, "[ServerStateStart] Client does not support the same version")
		return nil, nil, AlertProtocolVersion
	}

	// The client sent a cookie. So this is probably the second ClientHello (sent as a response to a HRR)
	var firstClientHello *HandshakeMessage
	var initialCipherSuite CipherSuiteParams // the cipher suite that was negotiated when sending the HelloRetryRequest
	if clientSentCookie {
		plainCookie, err := state.Config.CookieProtector.DecodeToken(clientCookie.Cookie)
		if err != nil {
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Error decoding token [%v]", err))
			return nil, nil, AlertDecryptError
		}
		cookie := &cookie{}
		if rb, err := syntax.Unmarshal(plainCookie, cookie); err != nil && rb != len(plainCookie) { // this should never happen
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Error unmarshaling cookie [%v]", err))
			return nil, nil, AlertInternalError
		}
		// restore the hash of initial ClientHello from the cookie
		firstClientHello = &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    cookie.ClientHelloHash,
		}
		// have the application validate its part of the cookie
		if state.Config.CookieHandler != nil && !state.Config.CookieHandler.Validate(state.conn, cookie.ApplicationCookie) {
			logf(logTypeHandshake, "[ServerStateStart] Cookie mismatch")
			return nil, nil, AlertAccessDenied
		}
		var ok bool
		initialCipherSuite, ok = cipherSuiteMap[cookie.CipherSuite]
		if !ok {
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Cookie contained invalid cipher suite: %#x", cookie.CipherSuite))
			return nil, nil, AlertInternalError
		}
	}

	if len(ch.LegacySessionID) != 0 && len(ch.LegacySessionID) != 32 {
		logf(logTypeHandshake, "[ServerStateStart] invalid session ID")
		return nil, nil, AlertIllegalParameter
	}

	// Figure out if we can do DH
	canDoDH, dhGroup, dhPublic, dhSecret := DHNegotiation(clientKeyShares.Shares, state.Config.Groups)

	// Figure out if we can do PSK
	var canDoPSK bool
	var selectedPSK int
	var params CipherSuiteParams
	var psk *PreSharedKey
	if len(clientPSK.Identities) > 0 {
		contextBase := []byte{}
		if clientSentCookie {
			contextBase = append(contextBase, firstClientHello.Marshal()...)
			// fill in the cookie sent by the client. Needed to calculate the correct hash
			cookieExt := &CookieExtension{Cookie: clientCookie.Cookie}
			hrr, err := state.generateHRR(params.Suite,
				ch.LegacySessionID, cookieExt)
			if err != nil {
				return nil, nil, AlertInternalError
			}
			contextBase = append(contextBase, hrr.Marshal()...)
		}
		chTrunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error computing truncated ClientHello [%v]", err)
			return nil, nil, AlertDecodeError
		}
		context := append(contextBase, chTrunc...)

		canDoPSK, selectedPSK, psk, params, err = PSKNegotiation(clientPSK.Identities, clientPSK.Binders, context, state.Config.PSKs)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error in PSK negotiation [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Figure out if we actually should do DH / PSK
	connParams.UsingDH, connParams.UsingPSK = PSKModeNegotiation(canDoDH, canDoPSK, clientPSKModes.KEModes)

	// Select a ciphersuite
	connParams.CipherSuite, err = CipherSuiteNegotiation(psk, ch.CipherSuites, state.Config.CipherSuites)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common ciphersuite found [%v]", err)
		return nil, nil, AlertHandshakeFailure
	}
	if clientSentCookie && initialCipherSuite.Suite != connParams.CipherSuite {
		logf(logTypeHandshake, "[ServerStateStart] Would have selected a different CipherSuite after receiving the client's Cookie")
		return nil, nil, AlertInternalError
	}

	var helloRetryRequest *HandshakeMessage
	if state.Config.RequireCookie {
		// Send a cookie if required
		// NB: Need to do this here because it's after ciphersuite selection, which
		// has to be after PSK selection.
		var shouldSendHRR bool
		var cookieExt *CookieExtension
		if !clientSentCookie { // this is the first ClientHello that we receive
			var appCookie []byte
			if state.Config.CookieHandler == nil { // if Config.RequireCookie is set, but no CookieHandler was provided, we definitely need to send a cookie
				shouldSendHRR = true
			} else { // if the CookieHandler was set, we just send a cookie when the application provides one
				var err error
				appCookie, err = state.Config.CookieHandler.Generate(state.conn)
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error generating cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				shouldSendHRR = appCookie != nil
			}
			if shouldSendHRR {
				params := cipherSuiteMap[connParams.CipherSuite]
				h := params.Hash.New()
				h.Write(clientHello.Marshal())
				plainCookie, err := syntax.Marshal(cookie{
					CipherSuite:       connParams.CipherSuite,
					ClientHelloHash:   h.Sum(nil),
					ApplicationCookie: appCookie,
				})
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error marshalling cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				cookieData, err := state.Config.CookieProtector.NewToken(plainCookie)
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error encoding cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				cookieExt = &CookieExtension{Cookie: cookieData}
			}
		} else {
			cookieExt = &CookieExtension{Cookie: clientCookie.Cookie}
		}

		// Generate a HRR. We will need it in both of the two cases:
		// 1. We need to send a Cookie. Then this HRR will be sent on the wire
		// 2. We need to validate a cookie. Then we need its hash
		// Ignoring errors because everything here is newly constructed, so there
		// shouldn't be marshal errors
		if shouldSendHRR || clientSentCookie {
			helloRetryRequest, err = state.generateHRR(connParams.CipherSuite,
				ch.LegacySessionID, cookieExt)
			if err != nil {
				return nil, nil, AlertInternalError
			}
		}

		if shouldSendHRR {
			toSend := []HandshakeAction{
				QueueHandshakeMessage{helloRetryRequest},
				SendQueuedHandshake{},
			}
			logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateStart]")
			return state, toSend, AlertStatelessRetry
		}
	}

	// If we've got no entropy to make keys from, fail
	if !connParams.UsingDH && !connParams.UsingPSK {
		logf(logTypeHandshake, "[ServerStateStart] Neither DH nor PSK negotiated")
		return nil, nil, AlertHandshakeFailure
	}

	var pskSecret []byte
	var cert *Certificate
	var certScheme SignatureScheme
	if connParams.UsingPSK {
		pskSecret = psk.Key
	} else {
		psk = nil

		// If we're not using a PSK mode, then we need to have certain extensions
		if !(foundExts[ExtensionTypeServerName] &&
			foundExts[ExtensionTypeSupportedGroups] &&
			foundExts[ExtensionTypeSignatureAlgorithms]) {
			logf(logTypeHandshake, "[ServerStateStart] Insufficient extensions (%v)", foundExts)
			return nil, nil, AlertMissingExtension
		}

		// Select a certificate
		name := string(*serverName)
		var err error
		cert, certScheme, err = CertificateSelection(&name, signatureAlgorithms.Algorithms, state.Config.Certificates)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] No appropriate certificate found [%v]", err)
			return nil, nil, AlertAccessDenied
		}
	}

	if !connParams.UsingDH {
		dhSecret = nil
	}

	// Figure out if we're going to do early data
	var clientEarlyTrafficSecret []byte
	connParams.ClientSendingEarlyData = foundExts[ExtensionTypeEarlyData]
	connParams.UsingEarlyData, connParams.RejectedEarlyData = EarlyDataNegotiation(connParams.UsingPSK, foundExts[ExtensionTypeEarlyData], state.Config.AllowEarlyData)
	if connParams.UsingEarlyData {
		h := params.Hash.New()
		h.Write(clientHello.Marshal())
		chHash := h.Sum(nil)

		zero := bytes.Repeat([]byte{0}, params.Hash.Size())
		earlySecret := HkdfExtract(params.Hash, zero, pskSecret)
		clientEarlyTrafficSecret = deriveSecret(params, earlySecret, labelEarlyTrafficSecret, chHash)
	}

	// Select a next protocol
	connParams.NextProto, err = ALPNNegotiation(psk, clientALPN.Protocols, state.Config.NextProtos)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common application-layer protocol found [%v]", err)
		return nil, nil, AlertNoApplicationProtocol
	}

	state.hsCtx.receivedEndOfFlight()

	logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateNegotiated]")
	state.hsCtx.SetVersion(tls12Version) // Everything after this should be 1.2.
	return serverStateNegotiated{
		Config:                   state.Config,
		Params:                   connParams,
		hsCtx:                    state.hsCtx,
		dhGroup:                  dhGroup,
		dhPublic:                 dhPublic,
		dhSecret:                 dhSecret,
		pskSecret:                pskSecret,
		selectedPSK:              selectedPSK,
		cert:                     cert,
		certScheme:               certScheme,
		legacySessionId:          ch.LegacySessionID,
		clientEarlyTrafficSecret: clientEarlyTrafficSecret,

		firstClientHello:  firstClientHello,
		helloRetryRequest: helloRetryRequest,
		clientHello:       clientHello,
	}, nil, AlertNoAlert
}

func (state *serverStateStart) generateHRR(cs CipherSuite, legacySessionId []byte,
	cookieExt *CookieExtension) (*HandshakeMessage, error) {
	var helloRetryRequest *HandshakeMessage
	hrr := &ServerHelloBody{
		Version:                 tls12Version,
		Random:                  hrrRandomSentinel,
		CipherSuite:             cs,
		LegacySessionID:         legacySessionId,
		LegacyCompressionMethod: 0,
	}

	sv := &SupportedVersionsExtension{
		HandshakeType: HandshakeTypeServerHello,
		Versions:      []uint16{supportedVersion},
	}

	if err := hrr.Extensions.Add(sv); err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error adding SupportedVersion [%v]", err)
		return nil, err
	}

	if err := hrr.Extensions.Add(cookieExt); err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error adding CookieExtension [%v]", err)
		return nil, err
	}
	// Run the external extension handler.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Send(HandshakeTypeHelloRetryRequest, &hrr.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error running external extension sender [%v]", err)
			return nil, err
		}
	}
	helloRetryRequest, err := state.hsCtx.hOut.HandshakeMessageFromBody(hrr)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error marshaling HRR [%v]", err)
		return nil, err
	}
	return helloRetryRequest, nil
}

type serverStateNegotiated struct {
	Config                   *Config
	Params                   ConnectionParameters
	hsCtx                    *HandshakeContext
	dhGroup                  NamedGroup
	dhPublic                 []byte
	dhSecret                 []byte
	pskSecret                []byte
	clientEarlyTrafficSecret []byte
	selectedPSK              int
	cert                     *Certificate
	certScheme               SignatureScheme
	legacySessionId          []byte
	firstClientHello         *HandshakeMessage
	helloRetryRequest        *HandshakeMessage
	clientHello              *HandshakeMessage
}

var _ HandshakeState = &serverStateNegotiated{}

func (state serverStateNegotiated) State() State {
	return StateServerNegotiated
}

func (state serverStateNegotiated) Next(_ handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	// Create the ServerHello
	sh := &ServerHelloBody{
		Version:                 tls12Version,
		CipherSuite:             state.Params.CipherSuite,
		LegacySessionID:         state.legacySessionId,
		LegacyCompressionMethod: 0,
	}
	if _, err := prng.Read(sh.Random[:]); err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error creating server random [%v]", err)
		return nil, nil, AlertInternalError
	}

	err := sh.Extensions.Add(&SupportedVersionsExtension{
		HandshakeType: HandshakeTypeServerHello,
		Versions:      []uint16{supportedVersion},
	})
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error adding supported_versions extension [%v]", err)
		return nil, nil, AlertInternalError
	}
	if state.Params.UsingDH {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending DH extension")
		err := sh.Extensions.Add(&KeyShareExtension{
			HandshakeType: HandshakeTypeServerHello,
			Shares:        []KeyShareEntry{{Group: state.dhGroup, KeyExchange: state.dhPublic}},
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding key_shares extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.Params.UsingPSK {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending PSK extension")
		err := sh.Extensions.Add(&PreSharedKeyExtension{
			HandshakeType:    HandshakeTypeServerHello,
			SelectedIdentity: uint16(state.selectedPSK),
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding PSK extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Run the external extension handler.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Send(HandshakeTypeServerHello, &sh.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error running external extension sender [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	serverHello, err := state.hsCtx.hOut.HandshakeMessageFromBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling ServerHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Look up crypto params
	params, ok := cipherSuiteMap[sh.CipherSuite]
	if !ok {
		logf(logTypeCrypto, "Unsupported ciphersuite [%04x]", sh.CipherSuite)
		return nil, nil, AlertHandshakeFailure
	}

	// Start up the handshake hash
	handshakeHash := params.Hash.New()
	handshakeHash.Write(state.firstClientHello.Marshal())
	handshakeHash.Write(state.helloRetryRequest.Marshal())
	handshakeHash.Write(state.clientHello.Marshal())
	handshakeHash.Write(serverHello.Marshal())

	// Compute handshake secrets
	zero := bytes.Repeat([]byte{0}, params.Hash.Size())

	var earlySecret []byte
	if state.Params.UsingPSK {
		earlySecret = HkdfExtract(params.Hash, zero, state.pskSecret)
	} else {
		earlySecret = HkdfExtract(params.Hash, zero, zero)
	}

	if state.dhSecret == nil {
		state.dhSecret = zero
	}

	h0 := params.Hash.New().Sum(nil)
	h2 := handshakeHash.Sum(nil)
	preHandshakeSecret := deriveSecret(params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(params.Hash, preHandshakeSecret, state.dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(params.Hash, preMasterSecret, zero)

	logf(logTypeCrypto, "early secret (init!): [%d] %x", len(earlySecret), earlySecret)
	logf(logTypeCrypto, "handshake secret: [%d] %x", len(handshakeSecret), handshakeSecret)
	logf(logTypeCrypto, "client handshake traffic secret: [%d] %x", len(clientHandshakeTrafficSecret), clientHandshakeTrafficSecret)
	logf(logTypeCrypto, "server handshake traffic secret: [%d] %x", len(serverHandshakeTrafficSecret), serverHandshakeTrafficSecret)
	logf(logTypeCrypto, "master secret: [%d] %x", len(masterSecret), masterSecret)

	clientHandshakeKeys := makeTrafficKeys(params, clientHandshakeTrafficSecret)
	serverHandshakeKeys := makeTrafficKeys(params, serverHandshakeTrafficSecret)

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := ExtensionList{}
	if state.Params.NextProto != "" {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(&ALPNExtension{Protocols: []string{state.Params.NextProto}})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding ALPN to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.Params.UsingEarlyData {
		logf(logTypeHandshake, "[server] sending EDI extension")
		err = eeList.Add(&EarlyDataExtension{})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding EDI to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	ee := &EncryptedExtensionsBody{eeList}

	// Run the external extension handler.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Send(HandshakeTypeEncryptedExtensions, &ee.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error running external extension sender [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	eem, err := state.hsCtx.hOut.HandshakeMessageFromBody(ee)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling EncryptedExtensions [%v]", err)
		return nil, nil, AlertInternalError
	}

	handshakeHash.Write(eem.Marshal())

	toSend := []HandshakeAction{
		QueueHandshakeMessage{serverHello},
		RekeyOut{epoch: EpochHandshakeData, KeySet: serverHandshakeKeys},
		QueueHandshakeMessage{eem},
	}

	// Authenticate with a certificate if required
	if !state.Params.UsingPSK {
		// Send a CertificateRequest message if we want client auth
		if state.Config.RequireClientAuth {
			state.Params.UsingClientAuth = true

			// XXX: We don't support sending any constraints besides a list of
			// supported signature algorithms
			cr := &CertificateRequestBody{}
			schemes := &SignatureAlgorithmsExtension{Algorithms: state.Config.SignatureSchemes}
			err := cr.Extensions.Add(schemes)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error adding supported schemes to CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}

			crm, err := state.hsCtx.hOut.HandshakeMessageFromBody(cr)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}
			//TODO state.state.serverCertificateRequest = cr

			toSend = append(toSend, QueueHandshakeMessage{crm})
			handshakeHash.Write(crm.Marshal())
		}

		// Create and send Certificate, CertificateVerify
		certificate := &CertificateBody{
			CertificateList: make([]CertificateEntry, len(state.cert.Chain)),
		}
		for i, entry := range state.cert.Chain {
			certificate.CertificateList[i] = CertificateEntry{CertData: entry}
		}
		certm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificate)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling Certificate [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, QueueHandshakeMessage{certm})
		handshakeHash.Write(certm.Marshal())

		certificateVerify := &CertificateVerifyBody{Algorithm: state.certScheme}
		logf(logTypeHandshake, "Creating CertVerify: %04x %v", state.certScheme, params.Hash)

		hcv := handshakeHash.Sum(nil)
		logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

		err = certificateVerify.Sign(state.cert.PrivateKey, hcv)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error signing CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}
		certvm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificateVerify)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, QueueHandshakeMessage{certvm})
		handshakeHash.Write(certvm.Marshal())
	}

	// Compute secrets resulting from the server's first flight
	h3 := handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d] %x", len(h3), h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h3), h3)

	serverFinishedData := computeFinishedData(params, serverHandshakeTrafficSecret, h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(serverFinishedData), serverFinishedData)

	// Assemble the Finished message
	fin := &FinishedBody{
		VerifyDataLen: len(serverFinishedData),
		VerifyData:    serverFinishedData,
	}
	finm, _ := state.hsCtx.hOut.HandshakeMessageFromBody(fin)

	toSend = append(toSend, QueueHandshakeMessage{finm})
	handshakeHash.Write(finm.Marshal())
	toSend = append(toSend, SendQueuedHandshake{})

	// Compute traffic secrets
	h4 := handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d] %x", len(h4), h4)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h4), h4)

	clientTrafficSecret := deriveSecret(params, masterSecret, labelClientApplicationTrafficSecret, h4)
	serverTrafficSecret := deriveSecret(params, masterSecret, labelServerApplicationTrafficSecret, h4)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(clientTrafficSecret), clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(serverTrafficSecret), serverTrafficSecret)

	serverTrafficKeys := makeTrafficKeys(params, serverTrafficSecret)
	toSend = append(toSend, RekeyOut{epoch: EpochApplicationData, KeySet: serverTrafficKeys})

	exporterSecret := deriveSecret(params, masterSecret, labelExporterSecret, h4)
	logf(logTypeCrypto, "server exporter secret: [%d] %x", len(exporterSecret), exporterSecret)

	if state.Params.UsingEarlyData {
		clientEarlyTrafficKeys := makeTrafficKeys(params, state.clientEarlyTrafficSecret)

		logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitEOED]")
		nextState := serverStateWaitEOED{
			Config:                       state.Config,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 params,
			handshakeHash:                handshakeHash,
			masterSecret:                 masterSecret,
			clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
			clientTrafficSecret:          clientTrafficSecret,
			serverTrafficSecret:          serverTrafficSecret,
			exporterSecret:               exporterSecret,
		}
		toSend = append(toSend, []HandshakeAction{
			RekeyIn{epoch: EpochEarlyData, KeySet: clientEarlyTrafficKeys},
		}...)
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitFlight2]")
	toSend = append(toSend, []HandshakeAction{
		RekeyIn{epoch: EpochHandshakeData, KeySet: clientHandshakeKeys},
	}...)
	var nextState HandshakeState
	nextState = serverStateWaitFlight2{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 params,
		handshakeHash:                handshakeHash,
		masterSecret:                 masterSecret,
		clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
		clientTrafficSecret:          clientTrafficSecret,
		serverTrafficSecret:          serverTrafficSecret,
		exporterSecret:               exporterSecret,
	}
	if state.Params.RejectedEarlyData {
		nextState = serverStateReadPastEarlyData{
			hsCtx: state.hsCtx,
			next:  &nextState,
		}
	}
	return nextState, toSend, AlertNoAlert
}

type serverStateWaitEOED struct {
	Config                       *Config
	Params                       ConnectionParameters
	hsCtx                        *HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &serverStateWaitEOED{}

func (state serverStateWaitEOED) State() State {
	return StateServerWaitEOED
}

func (state serverStateWaitEOED) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	for {
		logf(logTypeHandshake, "Server reading early data...")
		assert(state.hsCtx.hIn.conn.cipher.epoch == EpochEarlyData)
		t, err := state.hsCtx.hIn.conn.PeekRecordType(!state.hsCtx.hIn.nonblocking)
		if err == AlertWouldBlock {
			return nil, nil, AlertWouldBlock
		}

		if err != nil {
			logf(logTypeHandshake, "Server Error reading record type (1): %v", err)
			return nil, nil, AlertBadRecordMAC
		}

		logf(logTypeHandshake, "Server got record type(1): %v", t)

		if t != RecordTypeApplicationData {
			break
		}

		// Read a record into the buffer. Note that this is safe
		// in blocking mode because we read the record in
		// PeekRecordType.
		pt, err := state.hsCtx.hIn.conn.ReadRecord()
		if err != nil {
			logf(logTypeHandshake, "Server error reading early data record: %v", err)
			return nil, nil, AlertInternalError
		}

		logf(logTypeHandshake, "Server read early data: %x", pt.fragment)
		state.hsCtx.earlyData = append(state.hsCtx.earlyData, pt.fragment...)
	}

	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeEndOfEarlyData {
		logf(logTypeHandshake, "[ServerStateWaitEOED] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	if len(hm.body) > 0 {
		logf(logTypeHandshake, "[ServerStateWaitEOED] Error decoding message [len > 0]")
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	clientHandshakeKeys := makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)

	logf(logTypeHandshake, "[ServerStateWaitEOED] -> [ServerStateWaitFlight2]")
	toSend := []HandshakeAction{
		RekeyIn{epoch: EpochHandshakeData, KeySet: clientHandshakeKeys},
	}
	waitFlight2 := serverStateWaitFlight2{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
	}
	return waitFlight2, toSend, AlertNoAlert
}

var _ HandshakeState = &serverStateReadPastEarlyData{}

type serverStateReadPastEarlyData struct {
	hsCtx *HandshakeContext
	next  *HandshakeState
}

func (state serverStateReadPastEarlyData) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	for {
		logf(logTypeHandshake, "Server reading past early data...")
		// Scan past all records that fail to decrypt
		_, err := state.hsCtx.hIn.conn.PeekRecordType(!state.hsCtx.hIn.nonblocking)
		if err == nil {
			break
		}

		if err == AlertWouldBlock {
			return nil, nil, AlertWouldBlock
		}

		// Continue on DecryptError
		_, ok := err.(DecryptError)
		if !ok {
			return nil, nil, AlertInternalError // Really need something else.
		}
	}

	return *state.next, nil, AlertNoAlert
}

func (state serverStateReadPastEarlyData) State() State {
	return StateServerReadPastEarlyData
}

type serverStateWaitFlight2 struct {
	Config                       *Config
	Params                       ConnectionParameters
	hsCtx                        *HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &serverStateWaitFlight2{}

func (state serverStateWaitFlight2) State() State {
	return StateServerWaitFlight2
}

func (state serverStateWaitFlight2) Next(_ handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	if state.Params.UsingClientAuth {
		logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitCert]")
		nextState := serverStateWaitCert{
			Config:                       state.Config,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
			exporterSecret:               state.exporterSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitFinished]")
	nextState := serverStateWaitFinished{
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
	}
	return nextState, nil, AlertNoAlert
}

type serverStateWaitCert struct {
	Config                       *Config
	Params                       ConnectionParameters
	hsCtx                        *HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &serverStateWaitCert{}

func (state serverStateWaitCert) State() State {
	return StateServerWaitCert
}

func (state serverStateWaitCert) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	if err := safeUnmarshal(cert, hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	if len(cert.CertificateList) == 0 {
		logf(logTypeHandshake, "[ServerStateWaitCert] WARNING client did not provide a certificate")

		logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitFinished]")
		nextState := serverStateWaitFinished{
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			handshakeHash:                state.handshakeHash,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
			exporterSecret:               state.exporterSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitCV]")
	nextState := serverStateWaitCV{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		clientCertificate:            cert,
		exporterSecret:               state.exporterSecret,
	}
	return nextState, nil, AlertNoAlert
}

type serverStateWaitCV struct {
	Config       *Config
	Params       ConnectionParameters
	hsCtx        *HandshakeContext
	cryptoParams CipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte

	clientCertificate *CertificateBody
}

var _ HandshakeState = &serverStateWaitCV{}

func (state serverStateWaitCV) State() State {
	return StateServerWaitCV
}

func (state serverStateWaitCV) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ServerStateWaitCV] Unexpected message [%+v] [%s]", hm, reflect.TypeOf(hm))
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := &CertificateVerifyBody{}
	if err := safeUnmarshal(certVerify, hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCert] Error decoding message %v", err)
		return nil, nil, AlertDecodeError
	}

	rawCerts := make([][]byte, len(state.clientCertificate.CertificateList))
	certs := make([]*x509.Certificate, len(state.clientCertificate.CertificateList))
	for i, certEntry := range state.clientCertificate.CertificateList {
		certs[i] = certEntry.CertData
		rawCerts[i] = certEntry.CertData.Raw
	}

	// Verify client signature over handshake hash
	hcv := state.handshakeHash.Sum(nil)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

	clientPublicKey := state.clientCertificate.CertificateList[0].CertData.PublicKey
	if err := certVerify.Verify(clientPublicKey, hcv); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCV] Failure in client auth verification [%v]", err)
		return nil, nil, AlertHandshakeFailure
	}

	if state.Config.VerifyPeerCertificate != nil {
		// TODO(#171): pass in the verified chains, once we support different client auth types
		if err := state.Config.VerifyPeerCertificate(rawCerts, nil); err != nil {
			logf(logTypeHandshake, "[ServerStateWaitCV] Application rejected client certificate: %s", err)
			return nil, nil, AlertBadCertificate
		}
	}

	// If it passes, record the certificateVerify in the transcript hash
	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ServerStateWaitCV] -> [ServerStateWaitFinished]")
	nextState := serverStateWaitFinished{
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
		peerCertificates:             certs,
		verifiedChains:               nil, // TODO(#171): set this value
	}
	return nextState, nil, AlertNoAlert
}

type serverStateWaitFinished struct {
	Params       ConnectionParameters
	hsCtx        *HandshakeContext
	cryptoParams CipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	peerCertificates             []*x509.Certificate
	verifiedChains               [][]*x509.Certificate

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte
}

var _ HandshakeState = &serverStateWaitFinished{}

func (state serverStateWaitFinished) State() State {
	return StateServerWaitFinished
}

func (state serverStateWaitFinished) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	fin := &FinishedBody{VerifyDataLen: state.cryptoParams.Hash.Size()}
	if err := safeUnmarshal(fin, hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Error decoding message %v", err)
		return nil, nil, AlertDecodeError
	}

	// Verify client Finished data
	h5 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(h5), h5)

	clientFinishedData := computeFinishedData(state.cryptoParams, state.clientHandshakeTrafficSecret, h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(clientFinishedData), clientFinishedData)

	if !bytes.Equal(fin.VerifyData, clientFinishedData) {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Client's Finished failed to verify")
		return nil, nil, AlertHandshakeFailure
	}

	// Compute the resumption secret
	state.handshakeHash.Write(hm.Marshal())
	h6 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 6 [%d]: %x", len(h6), h6)

	resumptionSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelResumptionSecret, h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(resumptionSecret), resumptionSecret)

	// Compute client traffic keys
	clientTrafficKeys := makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)

	state.hsCtx.receivedFinalFlight()

	logf(logTypeHandshake, "[ServerStateWaitFinished] -> [StateConnected]")
	nextState := stateConnected{
		Params:              state.Params,
		hsCtx:               state.hsCtx,
		isClient:            false,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: state.clientTrafficSecret,
		serverTrafficSecret: state.serverTrafficSecret,
		exporterSecret:      state.exporterSecret,
		peerCertificates:    state.peerCertificates,
		verifiedChains:      state.verifiedChains,
	}
	toSend := []HandshakeAction{
		RekeyIn{epoch: EpochApplicationData, KeySet: clientTrafficKeys},
	}
	return nextState, toSend, AlertNoAlert
}
