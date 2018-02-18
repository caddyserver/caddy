package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

type serverConfigClient struct {
	raw    []byte
	ID     []byte
	obit   []byte
	expiry time.Time

	kex          crypto.KeyExchange
	sharedSecret []byte
}

var (
	errMessageNotServerConfig = errors.New("ServerConfig must have TagSCFG")
)

// parseServerConfig parses a server config
func parseServerConfig(data []byte) (*serverConfigClient, error) {
	message, err := ParseHandshakeMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if message.Tag != TagSCFG {
		return nil, errMessageNotServerConfig
	}

	scfg := &serverConfigClient{raw: data}
	err = scfg.parseValues(message.Data)
	if err != nil {
		return nil, err
	}

	return scfg, nil
}

func (s *serverConfigClient) parseValues(tagMap map[Tag][]byte) error {
	// SCID
	scfgID, ok := tagMap[TagSCID]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "SCID")
	}
	if len(scfgID) != 16 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "SCID")
	}
	s.ID = scfgID

	// KEXS
	// TODO: setup Key Exchange
	kexs, ok := tagMap[TagKEXS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "KEXS")
	}
	if len(kexs)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "KEXS")
	}
	c255Foundat := -1

	for i := 0; i < len(kexs)/4; i++ {
		if bytes.Equal(kexs[4*i:4*i+4], []byte("C255")) {
			c255Foundat = i
			break
		}
	}
	if c255Foundat < 0 {
		return qerr.Error(qerr.CryptoNoSupport, "KEXS: Could not find C255, other key exchanges are not supported")
	}

	// AEAD
	aead, ok := tagMap[TagAEAD]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "AEAD")
	}
	if len(aead)%4 != 0 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "AEAD")
	}
	var aesgFound bool
	for i := 0; i < len(aead)/4; i++ {
		if bytes.Equal(aead[4*i:4*i+4], []byte("AESG")) {
			aesgFound = true
			break
		}
	}
	if !aesgFound {
		return qerr.Error(qerr.CryptoNoSupport, "AEAD")
	}

	// PUBS
	pubs, ok := tagMap[TagPUBS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")
	}

	var pubs_kexs []struct{Length uint32; Value []byte}
	var last_len uint32

	for i := 0; i < len(pubs)-3; i += int(last_len)+3 {
		// the PUBS value is always prepended by 3 byte little endian length field

		err := binary.Read(bytes.NewReader([]byte{pubs[i], pubs[i+1], pubs[i+2], 0x00}), binary.LittleEndian, &last_len);
		if err != nil {
			return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS not decodable")
		}
		if last_len == 0 {
			return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS")
		}

		if i+3+int(last_len) > len(pubs) {
			return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS")
		}

		pubs_kexs = append(pubs_kexs, struct{Length uint32; Value []byte}{last_len, pubs[i+3:i+3+int(last_len)]})
	}

	if c255Foundat >= len(pubs_kexs) {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "KEXS not in PUBS")
	}

	if pubs_kexs[c255Foundat].Length != 32 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "PUBS")
	}

	var err error
	s.kex, err = crypto.NewCurve25519KEX()
	if err != nil {
		return err
	}


	s.sharedSecret, err = s.kex.CalculateSharedKey(pubs_kexs[c255Foundat].Value)
	if err != nil {
		return err
	}

	// OBIT
	obit, ok := tagMap[TagOBIT]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "OBIT")
	}
	if len(obit) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "OBIT")
	}
	s.obit = obit

	// EXPY
	expy, ok := tagMap[TagEXPY]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "EXPY")
	}
	if len(expy) != 8 {
		return qerr.Error(qerr.CryptoInvalidValueLength, "EXPY")
	}
	// make sure that the value doesn't overflow an int64
	// furthermore, values close to MaxInt64 are not a valid input to time.Unix, thus set MaxInt64/2 as the maximum value here
	expyTimestamp := utils.MinUint64(binary.LittleEndian.Uint64(expy), math.MaxInt64/2)
	s.expiry = time.Unix(int64(expyTimestamp), 0)

	// TODO: implement VER

	return nil
}

func (s *serverConfigClient) IsExpired() bool {
	return s.expiry.Before(time.Now())
}

func (s *serverConfigClient) Get() []byte {
	return s.raw
}
