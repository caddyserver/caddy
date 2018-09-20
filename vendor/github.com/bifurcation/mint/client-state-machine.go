package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"hash"
	"time"
)

// Client State Machine
//
//                            START <----+
//             Send ClientHello |        | Recv HelloRetryRequest
//          /                   v        |
//         |                  WAIT_SH ---+
//     Can |                    | Recv ServerHello
//    send |                    V
//   early |                 WAIT_EE
//    data |                    | Recv EncryptedExtensions
//         |           +--------+--------+
//         |     Using |                 | Using certificate
//         |       PSK |                 v
//         |           |            WAIT_CERT_CR
//         |           |        Recv |       | Recv CertificateRequest
//         |           | Certificate |       v
//         |           |             |    WAIT_CERT
//         |           |             |       | Recv Certificate
//         |           |             v       v
//         |           |              WAIT_CV
//         |           |                 | Recv CertificateVerify
//         |           +> WAIT_FINISHED <+
//         |                  | Recv Finished
//         \                  |
//                            | [Send EndOfEarlyData]
//                            | [Send Certificate [+ CertificateVerify]]
//                            | Send Finished
//  Can send                  v
//  app data -->          CONNECTED
//  after
//  here
//
//  State							Instructions
//  START							Send(CH); [RekeyOut; SendEarlyData]
//  WAIT_SH						Send(CH) || RekeyIn
//  WAIT_EE						{}
//  WAIT_CERT_CR			{}
//  WAIT_CERT					{}
//  WAIT_CV						{}
//  WAIT_FINISHED			RekeyIn; [Send(EOED);] RekeyOut; [SendCert; SendCV;] SendFin; RekeyOut;
//  CONNECTED					StoreTicket || (RekeyIn; [RekeyOut])

type clientStateStart struct {
	Config *Config
	Opts   ConnectionOptions
	Params ConnectionParameters

	cookie            []byte
	firstClientHello  *HandshakeMessage
	helloRetryRequest *HandshakeMessage
	hsCtx             *HandshakeContext
}

var _ HandshakeState = &clientStateStart{}

func (state clientStateStart) State() State {
	return StateClientStart
}

func (state clientStateStart) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	// key_shares
	offeredDH := map[NamedGroup][]byte{}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares:        make([]KeyShareEntry, len(state.Config.Groups)),
	}
	for i, group := range state.Config.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error generating key share [%v]", err)
			return nil, nil, AlertInternalError
		}

		ks.Shares[i].Group = group
		ks.Shares[i].KeyExchange = pub
		offeredDH[group] = priv
	}

	logf(logTypeHandshake, "opts: %+v", state.Opts)

	// supported_versions, supported_groups, signature_algorithms, server_name
	sv := SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello, Versions: []uint16{supportedVersion}}
	sni := ServerNameExtension(state.Opts.ServerName)
	sg := SupportedGroupsExtension{Groups: state.Config.Groups}
	sa := SignatureAlgorithmsExtension{Algorithms: state.Config.SignatureSchemes}

	state.Params.ServerName = state.Opts.ServerName

	// Application Layer Protocol Negotiation
	var alpn *ALPNExtension
	if (state.Opts.NextProtos != nil) && (len(state.Opts.NextProtos) > 0) {
		alpn = &ALPNExtension{Protocols: state.Opts.NextProtos}
	}

	// Construct base ClientHello
	ch := &ClientHelloBody{
		LegacyVersion: wireVersion(state.hsCtx.hIn),
		CipherSuites:  state.Config.CipherSuites,
	}
	_, err := prng.Read(ch.Random[:])
	if err != nil {
		logf(logTypeHandshake, "[ClientStateStart] Error creating ClientHello random [%v]", err)
		return nil, nil, AlertInternalError
	}
	for _, ext := range []ExtensionBody{&sv, &sni, &ks, &sg, &sa} {
		err := ch.Extensions.Add(ext)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding extension type=[%v] [%v]", ext.Type(), err)
			return nil, nil, AlertInternalError
		}
	}
	// XXX: These optional extensions can't be folded into the above because Go
	// interface-typed values are never reported as nil
	if alpn != nil {
		err := ch.Extensions.Add(alpn)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.cookie != nil {
		err := ch.Extensions.Add(&CookieExtension{Cookie: state.cookie})
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Run the external extension handler.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Send(HandshakeTypeClientHello, &ch.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error running external extension sender [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Handle PSK and EarlyData just before transmitting, so that we can
	// calculate the PSK binder value
	var psk *PreSharedKeyExtension
	var ed *EarlyDataExtension
	var offeredPSK PreSharedKey
	var earlyHash crypto.Hash
	var earlySecret []byte
	var clientEarlyTrafficKeys keySet
	var clientHello *HandshakeMessage
	if key, ok := state.Config.PSKs.Get(state.Opts.ServerName); ok {
		offeredPSK = key

		// Narrow ciphersuites to ones that match PSK hash
		params, ok := cipherSuiteMap[key.CipherSuite]
		if !ok {
			logf(logTypeHandshake, "[ClientStateStart] PSK for unknown ciphersuite")
			return nil, nil, AlertInternalError
		}

		compatibleSuites := []CipherSuite{}
		for _, suite := range ch.CipherSuites {
			if cipherSuiteMap[suite].Hash == params.Hash {
				compatibleSuites = append(compatibleSuites, suite)
			}
		}
		ch.CipherSuites = compatibleSuites

		// TODO(ekr@rtfm.com): Check that the ticket can be used for early
		// data.
		// Signal early data if we're going to do it
		if state.Config.AllowEarlyData && state.helloRetryRequest == nil {
			state.Params.ClientSendingEarlyData = true
			ed = &EarlyDataExtension{}
			err = ch.Extensions.Add(ed)
			if err != nil {
				logf(logTypeHandshake, "Error adding early data extension: %v", err)
				return nil, nil, AlertInternalError
			}
		}

		// Signal supported PSK key exchange modes
		if len(state.Config.PSKModes) == 0 {
			logf(logTypeHandshake, "PSK selected, but no PSKModes")
			return nil, nil, AlertInternalError
		}
		kem := &PSKKeyExchangeModesExtension{KEModes: state.Config.PSKModes}
		err = ch.Extensions.Add(kem)
		if err != nil {
			logf(logTypeHandshake, "Error adding PSKKeyExchangeModes extension: %v", err)
			return nil, nil, AlertInternalError
		}

		// Add the shim PSK extension to the ClientHello
		logf(logTypeHandshake, "Adding PSK extension with id = %x", key.Identity)
		psk = &PreSharedKeyExtension{
			HandshakeType: HandshakeTypeClientHello,
			Identities: []PSKIdentity{
				{
					Identity:            key.Identity,
					ObfuscatedTicketAge: uint32(time.Since(key.ReceivedAt)/time.Millisecond) + key.TicketAgeAdd,
				},
			},
			Binders: []PSKBinderEntry{
				// Note: Stub to get the length fields right
				{Binder: bytes.Repeat([]byte{0x00}, params.Hash.Size())},
			},
		}
		ch.Extensions.Add(psk)

		// Compute the binder key
		h0 := params.Hash.New().Sum(nil)
		zero := bytes.Repeat([]byte{0}, params.Hash.Size())

		earlyHash = params.Hash
		earlySecret = HkdfExtract(params.Hash, zero, key.Key)
		logf(logTypeCrypto, "early secret: [%d] %x", len(earlySecret), earlySecret)

		binderLabel := labelExternalBinder
		if key.IsResumption {
			binderLabel = labelResumptionBinder
		}
		binderKey := deriveSecret(params, earlySecret, binderLabel, h0)
		logf(logTypeCrypto, "binder key: [%d] %x", len(binderKey), binderKey)

		// Compute the binder value
		trunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error marshaling truncated ClientHello [%v]", err)
			return nil, nil, AlertInternalError
		}

		truncHash := params.Hash.New()
		truncHash.Write(trunc)

		binder := computeFinishedData(params, binderKey, truncHash.Sum(nil))

		// Replace the PSK extension
		psk.Binders[0].Binder = binder
		ch.Extensions.Add(psk)

		// If we got here, the earlier marshal succeeded (in ch.Truncated()), so
		// this one should too.
		clientHello, _ = state.hsCtx.hOut.HandshakeMessageFromBody(ch)

		// Compute early traffic keys
		h := params.Hash.New()
		h.Write(clientHello.Marshal())
		chHash := h.Sum(nil)

		earlyTrafficSecret := deriveSecret(params, earlySecret, labelEarlyTrafficSecret, chHash)
		logf(logTypeCrypto, "early traffic secret: [%d] %x", len(earlyTrafficSecret), earlyTrafficSecret)
		clientEarlyTrafficKeys = makeTrafficKeys(params, earlyTrafficSecret)
	} else {
		clientHello, err = state.hsCtx.hOut.HandshakeMessageFromBody(ch)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error marshaling ClientHello [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	logf(logTypeHandshake, "[ClientStateStart] -> [ClientStateWaitSH]")
	state.hsCtx.SetVersion(tls12Version) // Everything after this should be 1.2.
	nextState := clientStateWaitSH{
		Config:     state.Config,
		Opts:       state.Opts,
		Params:     state.Params,
		hsCtx:      state.hsCtx,
		OfferedDH:  offeredDH,
		OfferedPSK: offeredPSK,

		earlySecret: earlySecret,
		earlyHash:   earlyHash,

		firstClientHello:  state.firstClientHello,
		helloRetryRequest: state.helloRetryRequest,
		clientHello:       clientHello,
	}

	toSend := []HandshakeAction{
		QueueHandshakeMessage{clientHello},
		SendQueuedHandshake{},
	}
	if state.Params.ClientSendingEarlyData {
		toSend = append(toSend, []HandshakeAction{
			RekeyOut{epoch: EpochEarlyData, KeySet: clientEarlyTrafficKeys},
		}...)
	}

	return nextState, toSend, AlertNoAlert
}

type clientStateWaitSH struct {
	Config     *Config
	Opts       ConnectionOptions
	Params     ConnectionParameters
	hsCtx      *HandshakeContext
	OfferedDH  map[NamedGroup][]byte
	OfferedPSK PreSharedKey
	PSK        []byte

	earlySecret []byte
	earlyHash   crypto.Hash

	firstClientHello  *HandshakeMessage
	helloRetryRequest *HandshakeMessage
	clientHello       *HandshakeMessage
}

var _ HandshakeState = &clientStateWaitSH{}

func (state clientStateWaitSH) State() State {
	return StateClientWaitSH
}

func (state clientStateWaitSH) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}

	if hm == nil || hm.msgType != HandshakeTypeServerHello {
		logf(logTypeHandshake, "[ClientStateWaitSH] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	sh := &ServerHelloBody{}
	if _, err := sh.Unmarshal(hm.body); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// Common SH/HRR processing first.
	// 1. Check that sh.version is TLS 1.2
	if sh.Version != tls12Version {
		logf(logTypeHandshake, "[ClientStateWaitSH] illegal legacy version [%v]", sh.Version)
		return nil, nil, AlertIllegalParameter
	}

	// 2. Check that it responded with a valid version.
	supportedVersions := SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello}
	foundSupportedVersions, err := sh.Extensions.Find(&supportedVersions)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] invalid supported_versions extension [%v]", err)
		return nil, nil, AlertDecodeError
	}
	if !foundSupportedVersions {
		logf(logTypeHandshake, "[ClientStateWaitSH] no supported_versions extension")
		return nil, nil, AlertMissingExtension
	}
	if supportedVersions.Versions[0] != supportedVersion {
		logf(logTypeHandshake, "[ClientStateWaitSH] unsupported version [%x]", supportedVersions.Versions[0])
		return nil, nil, AlertProtocolVersion
	}
	// 3. Check that the server provided a supported ciphersuite
	supportedCipherSuite := false
	for _, suite := range state.Config.CipherSuites {
		supportedCipherSuite = supportedCipherSuite || (suite == sh.CipherSuite)
	}
	if !supportedCipherSuite {
		logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported ciphersuite [%04x]", sh.CipherSuite)
		return nil, nil, AlertHandshakeFailure
	}

	// Now check for the sentinel.

	if sh.Random == hrrRandomSentinel {
		// This is actually HRR.
		hrr := sh

		// Narrow the supported ciphersuites to the server-provided one
		state.Config.CipherSuites = []CipherSuite{hrr.CipherSuite}

		// Handle external extensions.
		if state.Config.ExtensionHandler != nil {
			err := state.Config.ExtensionHandler.Receive(HandshakeTypeHelloRetryRequest, &hrr.Extensions)
			if err != nil {
				logf(logTypeHandshake, "[ClientWaitSH] Error running external extension handler [%v]", err)
				return nil, nil, AlertInternalError
			}
		}

		// The only thing we know how to respond to in an HRR is the Cookie
		// extension, so if there is either no Cookie extension or anything other
		// than a Cookie extension and SupportedVersions we have to fail.
		serverCookie := new(CookieExtension)
		foundCookie, err := hrr.Extensions.Find(serverCookie)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitSH] Invalid server cookie extension [%v]", err)
			return nil, nil, AlertDecodeError
		}
		if !foundCookie || len(hrr.Extensions) != 2 {
			logf(logTypeHandshake, "[ClientStateWaitSH] No Cookie or extra extensions [%v] [%d]", foundCookie, len(hrr.Extensions))
			return nil, nil, AlertIllegalParameter
		}

		// Hash the body into a pseudo-message
		// XXX: Ignoring some errors here
		params := cipherSuiteMap[hrr.CipherSuite]
		h := params.Hash.New()
		h.Write(state.clientHello.Marshal())
		firstClientHello := &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    h.Sum(nil),
		}

		state.hsCtx.receivedEndOfFlight()

		// TODO(ekr@rtfm.com): Need to rekey with cleartext if we are on 0-RTT
		// mode. In DTLS, we also need to bump the sequence number.
		// This is a pre-existing defect in Mint. Issue #175.
		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateStart]")
		return clientStateStart{
			Config:            state.Config,
			Opts:              state.Opts,
			hsCtx:             state.hsCtx,
			cookie:            serverCookie.Cookie,
			firstClientHello:  firstClientHello,
			helloRetryRequest: hm,
		}, []HandshakeAction{ResetOut{1}}, AlertNoAlert
	}

	// This is SH.
	// Handle external extensions.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Receive(HandshakeTypeServerHello, &sh.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ClientWaitSH] Error running external extension handler [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Do PSK or key agreement depending on extensions
	serverPSK := PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
	serverKeyShare := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}

	foundExts, err := sh.Extensions.Parse(
		[]ExtensionBody{
			&serverPSK,
			&serverKeyShare,
		})
	if err != nil {
		logf(logTypeHandshake, "[ClientWaitSH] Error processing extensions [%v]", err)
		return nil, nil, AlertDecodeError
	}

	if foundExts[ExtensionTypePreSharedKey] && (serverPSK.SelectedIdentity == 0) {
		state.Params.UsingPSK = true
	}

	var dhSecret []byte
	if foundExts[ExtensionTypeKeyShare] {
		sks := serverKeyShare.Shares[0]
		priv, ok := state.OfferedDH[sks.Group]
		if !ok {
			logf(logTypeHandshake, "[ClientStateWaitSH] Key share for unknown group")
			return nil, nil, AlertIllegalParameter
		}

		state.Params.UsingDH = true
		dhSecret, _ = keyAgreement(sks.Group, sks.KeyExchange, priv)
	}

	suite := sh.CipherSuite
	state.Params.CipherSuite = suite

	params, ok := cipherSuiteMap[suite]
	if !ok {
		logf(logTypeCrypto, "Unsupported ciphersuite [%04x]", suite)
		return nil, nil, AlertHandshakeFailure
	}

	// Start up the handshake hash
	handshakeHash := params.Hash.New()
	handshakeHash.Write(state.firstClientHello.Marshal())
	handshakeHash.Write(state.helloRetryRequest.Marshal())
	handshakeHash.Write(state.clientHello.Marshal())
	handshakeHash.Write(hm.Marshal())

	// Compute handshake secrets
	zero := bytes.Repeat([]byte{0}, params.Hash.Size())

	var earlySecret []byte
	if state.Params.UsingPSK {
		if params.Hash != state.earlyHash {
			logf(logTypeCrypto, "Change of hash between early and normal init early=[%02x] suite=[%04x] hash=[%02x]",
				state.earlyHash, suite, params.Hash)
		}

		earlySecret = state.earlySecret
	} else {
		earlySecret = HkdfExtract(params.Hash, zero, zero)
	}

	if dhSecret == nil {
		dhSecret = zero
	}

	h0 := params.Hash.New().Sum(nil)
	h2 := handshakeHash.Sum(nil)
	preHandshakeSecret := deriveSecret(params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(params.Hash, preHandshakeSecret, dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(params.Hash, preMasterSecret, zero)

	logf(logTypeCrypto, "early secret: [%d] %x", len(earlySecret), earlySecret)
	logf(logTypeCrypto, "handshake secret: [%d] %x", len(handshakeSecret), handshakeSecret)
	logf(logTypeCrypto, "client handshake traffic secret: [%d] %x", len(clientHandshakeTrafficSecret), clientHandshakeTrafficSecret)
	logf(logTypeCrypto, "server handshake traffic secret: [%d] %x", len(serverHandshakeTrafficSecret), serverHandshakeTrafficSecret)
	logf(logTypeCrypto, "master secret: [%d] %x", len(masterSecret), masterSecret)

	serverHandshakeKeys := makeTrafficKeys(params, serverHandshakeTrafficSecret)
	logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitEE]")
	nextState := clientStateWaitEE{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 params,
		handshakeHash:                handshakeHash,
		masterSecret:                 masterSecret,
		clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: serverHandshakeTrafficSecret,
	}
	toSend := []HandshakeAction{
		RekeyIn{epoch: EpochHandshakeData, KeySet: serverHandshakeKeys},
	}
	// We're definitely not going to have to send anything with
	// early data.
	if !state.Params.ClientSendingEarlyData {
		toSend = append(toSend, RekeyOut{epoch: EpochHandshakeData,
			KeySet: makeTrafficKeys(params, clientHandshakeTrafficSecret)})
	}

	return nextState, toSend, AlertNoAlert
}

type clientStateWaitEE struct {
	Config                       *Config
	Params                       ConnectionParameters
	hsCtx                        *HandshakeContext
	cryptoParams                 CipherSuiteParams
	handshakeHash                hash.Hash
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

var _ HandshakeState = &clientStateWaitEE{}

func (state clientStateWaitEE) State() State {
	return StateClientWaitEE
}

func (state clientStateWaitEE) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeEncryptedExtensions {
		logf(logTypeHandshake, "[ClientStateWaitEE] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ee := EncryptedExtensionsBody{}
	if err := safeUnmarshal(&ee, hm.body); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitEE] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	// Handle external extensions.
	if state.Config.ExtensionHandler != nil {
		err := state.Config.ExtensionHandler.Receive(HandshakeTypeEncryptedExtensions, &ee.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ClientWaitStateEE] Error running external extension handler [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	serverALPN := &ALPNExtension{}
	serverEarlyData := &EarlyDataExtension{}

	foundExts, err := ee.Extensions.Parse(
		[]ExtensionBody{
			serverALPN,
			serverEarlyData,
		})
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitEE] Error decoding extensions: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.Params.UsingEarlyData = foundExts[ExtensionTypeEarlyData]

	if foundExts[ExtensionTypeALPN] && len(serverALPN.Protocols) > 0 {
		state.Params.NextProto = serverALPN.Protocols[0]
	}

	state.handshakeHash.Write(hm.Marshal())

	toSend := []HandshakeAction{}

	if state.Params.ClientSendingEarlyData && !state.Params.UsingEarlyData {
		// We didn't get 0-RTT, so rekey to handshake.
		toSend = append(toSend, RekeyOut{epoch: EpochHandshakeData,
			KeySet: makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)})
	}

	if state.Params.UsingPSK {
		logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitFinished]")
		nextState := clientStateWaitFinished{
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			certificates:                 state.Config.Certificates,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitCertCR]")
	nextState := clientStateWaitCertCR{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
	}
	return nextState, toSend, AlertNoAlert
}

type clientStateWaitCertCR struct {
	Config                       *Config
	Params                       ConnectionParameters
	hsCtx                        *HandshakeContext
	cryptoParams                 CipherSuiteParams
	handshakeHash                hash.Hash
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

var _ HandshakeState = &clientStateWaitCertCR{}

func (state clientStateWaitCertCR) State() State {
	return StateClientWaitCertCR
}

func (state clientStateWaitCertCR) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	switch body := bodyGeneric.(type) {
	case *CertificateBody:
		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCV]")
		nextState := clientStateWaitCV{
			Config:                       state.Config,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			serverCertificate:            body,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert

	case *CertificateRequestBody:
		// A certificate request in the handshake should have a zero-length context
		if len(body.CertificateRequestContext) > 0 {
			logf(logTypeHandshake, "[ClientStateWaitCertCR] Certificate request with non-empty context: %v", err)
			return nil, nil, AlertIllegalParameter
		}

		state.Params.UsingClientAuth = true

		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCert]")
		nextState := clientStateWaitCert{
			Config:                       state.Config,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			serverCertificateRequest:     body,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type clientStateWaitCert struct {
	Config        *Config
	Params        ConnectionParameters
	hsCtx         *HandshakeContext
	cryptoParams  CipherSuiteParams
	handshakeHash hash.Hash

	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

var _ HandshakeState = &clientStateWaitCert{}

func (state clientStateWaitCert) State() State {
	return StateClientWaitCert
}

func (state clientStateWaitCert) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ClientStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	if err := safeUnmarshal(cert, hm.body); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCert] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ClientStateWaitCert] -> [ClientStateWaitCV]")
	nextState := clientStateWaitCV{
		Config:                       state.Config,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		serverCertificate:            cert,
		serverCertificateRequest:     state.serverCertificateRequest,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type clientStateWaitCV struct {
	Config        *Config
	Params        ConnectionParameters
	hsCtx         *HandshakeContext
	cryptoParams  CipherSuiteParams
	handshakeHash hash.Hash

	serverCertificate        *CertificateBody
	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

var _ HandshakeState = &clientStateWaitCV{}

func (state clientStateWaitCV) State() State {
	return StateClientWaitCV
}

func (state clientStateWaitCV) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ClientStateWaitCV] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := CertificateVerifyBody{}
	if err := safeUnmarshal(&certVerify, hm.body); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	hcv := state.handshakeHash.Sum(nil)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

	serverPublicKey := state.serverCertificate.CertificateList[0].CertData.PublicKey
	if err := certVerify.Verify(serverPublicKey, hcv); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Server signature failed to verify")
		return nil, nil, AlertHandshakeFailure
	}

	certs := make([]*x509.Certificate, len(state.serverCertificate.CertificateList))
	rawCerts := make([][]byte, len(state.serverCertificate.CertificateList))
	for i, certEntry := range state.serverCertificate.CertificateList {
		certs[i] = certEntry.CertData
		rawCerts[i] = certEntry.CertData.Raw
	}

	var verifiedChains [][]*x509.Certificate
	if !state.Config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         state.Config.RootCAs,
			CurrentTime:   state.Config.time(),
			DNSName:       state.Config.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		for i, cert := range certs {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}
		var err error
		verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitCV] Certificate verification failed: %s", err)
			return nil, nil, AlertBadCertificate
		}
	}

	if state.Config.VerifyPeerCertificate != nil {
		if err := state.Config.VerifyPeerCertificate(rawCerts, verifiedChains); err != nil {
			logf(logTypeHandshake, "[ClientStateWaitCV] Application rejected server certificate: %s", err)
			return nil, nil, AlertBadCertificate
		}
	}

	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ClientStateWaitCV] -> [ClientStateWaitFinished]")
	nextState := clientStateWaitFinished{
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		certificates:                 state.Config.Certificates,
		serverCertificateRequest:     state.serverCertificateRequest,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.serverHandshakeTrafficSecret,
		peerCertificates:             certs,
		verifiedChains:               verifiedChains,
	}
	return nextState, nil, AlertNoAlert
}

type clientStateWaitFinished struct {
	Params        ConnectionParameters
	hsCtx         *HandshakeContext
	cryptoParams  CipherSuiteParams
	handshakeHash hash.Hash

	certificates             []*Certificate
	serverCertificateRequest *CertificateRequestBody
	peerCertificates         []*x509.Certificate
	verifiedChains           [][]*x509.Certificate

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

var _ HandshakeState = &clientStateWaitFinished{}

func (state clientStateWaitFinished) State() State {
	return StateClientWaitFinished
}

func (state clientStateWaitFinished) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// Verify server's Finished
	h3 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d] %x", len(h3), h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h3), h3)

	serverFinishedData := computeFinishedData(state.cryptoParams, state.serverHandshakeTrafficSecret, h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(serverFinishedData), serverFinishedData)

	fin := &FinishedBody{VerifyDataLen: len(serverFinishedData)}
	if err := safeUnmarshal(fin, hm.body); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	if !bytes.Equal(fin.VerifyData, serverFinishedData) {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Server's Finished failed to verify [%x] != [%x]",
			fin.VerifyData, serverFinishedData)
		return nil, nil, AlertHandshakeFailure
	}

	// Update the handshake hash with the Finished
	state.handshakeHash.Write(hm.Marshal())
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(hm.Marshal()), hm.Marshal())
	h4 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d]: %x", len(h4), h4)

	// Compute traffic secrets and keys
	clientTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelClientApplicationTrafficSecret, h4)
	serverTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelServerApplicationTrafficSecret, h4)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(clientTrafficSecret), clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(serverTrafficSecret), serverTrafficSecret)

	clientTrafficKeys := makeTrafficKeys(state.cryptoParams, clientTrafficSecret)
	serverTrafficKeys := makeTrafficKeys(state.cryptoParams, serverTrafficSecret)

	exporterSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelExporterSecret, h4)
	logf(logTypeCrypto, "client exporter secret: [%d] %x", len(exporterSecret), exporterSecret)

	// Assemble client's second flight
	toSend := []HandshakeAction{}

	if state.Params.UsingEarlyData {
		logf(logTypeHandshake, "Sending end of early data")
		// Note: We only send EOED if the server is actually going to use the early
		// data.  Otherwise, it will never see it, and the transcripts will
		// mismatch.
		// EOED marshal is infallible
		eoedm, _ := state.hsCtx.hOut.HandshakeMessageFromBody(&EndOfEarlyDataBody{})
		toSend = append(toSend, QueueHandshakeMessage{eoedm})

		state.handshakeHash.Write(eoedm.Marshal())
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(eoedm.Marshal()), eoedm.Marshal())

		// And then rekey to handshake
		toSend = append(toSend, RekeyOut{epoch: EpochHandshakeData,
			KeySet: makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)})
	}

	if state.Params.UsingClientAuth {
		// Extract constraints from certicateRequest
		schemes := SignatureAlgorithmsExtension{}
		gotSchemes, err := state.serverCertificateRequest.Extensions.Find(&schemes)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING invalid signature_schemes extension [%v]", err)
			return nil, nil, AlertDecodeError
		}
		if !gotSchemes {
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found")
			return nil, nil, AlertIllegalParameter
		}

		// Select a certificate
		cert, certScheme, err := CertificateSelection(nil, schemes.Algorithms, state.certificates)
		if err != nil {
			// XXX: Signal this to the application layer?
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found [%v]", err)

			certificate := &CertificateBody{}
			certm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, QueueHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())
		} else {
			// Create and send Certificate, CertificateVerify
			certificate := &CertificateBody{
				CertificateList: make([]CertificateEntry, len(cert.Chain)),
			}
			for i, entry := range cert.Chain {
				certificate.CertificateList[i] = CertificateEntry{CertData: entry}
			}
			certm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, QueueHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())

			hcv := state.handshakeHash.Sum(nil)
			logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

			certificateVerify := &CertificateVerifyBody{Algorithm: certScheme}
			logf(logTypeHandshake, "Creating CertVerify: %04x %v", certScheme, state.cryptoParams.Hash)

			err = certificateVerify.Sign(cert.PrivateKey, hcv)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error signing CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}
			certvm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificateVerify)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, QueueHandshakeMessage{certvm})
			state.handshakeHash.Write(certvm.Marshal())
		}
	}

	// Compute the client's Finished message
	h5 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(h5), h5)

	clientFinishedData := computeFinishedData(state.cryptoParams, state.clientHandshakeTrafficSecret, h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(clientFinishedData), clientFinishedData)

	fin = &FinishedBody{
		VerifyDataLen: len(clientFinishedData),
		VerifyData:    clientFinishedData,
	}
	finm, err := state.hsCtx.hOut.HandshakeMessageFromBody(fin)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling client Finished [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Compute the resumption secret
	state.handshakeHash.Write(finm.Marshal())
	h6 := state.handshakeHash.Sum(nil)

	resumptionSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelResumptionSecret, h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(resumptionSecret), resumptionSecret)

	toSend = append(toSend, []HandshakeAction{
		QueueHandshakeMessage{finm},
		SendQueuedHandshake{},
		RekeyIn{epoch: EpochApplicationData, KeySet: serverTrafficKeys},
		RekeyOut{epoch: EpochApplicationData, KeySet: clientTrafficKeys},
	}...)

	state.hsCtx.receivedEndOfFlight()

	logf(logTypeHandshake, "[ClientStateWaitFinished] -> [StateConnected]")
	nextState := stateConnected{
		Params:              state.Params,
		hsCtx:               state.hsCtx,
		isClient:            true,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: clientTrafficSecret,
		serverTrafficSecret: serverTrafficSecret,
		exporterSecret:      exporterSecret,
		peerCertificates:    state.peerCertificates,
		verifiedChains:      state.verifiedChains,
	}
	return nextState, toSend, AlertNoAlert
}
