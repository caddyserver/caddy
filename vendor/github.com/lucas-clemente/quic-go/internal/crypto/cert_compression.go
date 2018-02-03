package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

type entryType uint8

const (
	entryCompressed entryType = 1
	entryCached     entryType = 2
	entryCommon     entryType = 3
)

type entry struct {
	t entryType
	h uint64 // set hash
	i uint32 // index
}

func compressChain(chain [][]byte, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	res := &bytes.Buffer{}

	cachedHashes, err := splitHashes(pCachedHashes)
	if err != nil {
		return nil, err
	}

	setHashes, err := splitHashes(pCommonSetHashes)
	if err != nil {
		return nil, err
	}

	chainHashes := make([]uint64, len(chain))
	for i := range chain {
		chainHashes[i] = HashCert(chain[i])
	}

	entries := buildEntries(chain, chainHashes, cachedHashes, setHashes)

	totalUncompressedLen := 0
	for i, e := range entries {
		res.WriteByte(uint8(e.t))
		switch e.t {
		case entryCached:
			utils.LittleEndian.WriteUint64(res, e.h)
		case entryCommon:
			utils.LittleEndian.WriteUint64(res, e.h)
			utils.LittleEndian.WriteUint32(res, e.i)
		case entryCompressed:
			totalUncompressedLen += 4 + len(chain[i])
		}
	}
	res.WriteByte(0) // end of list

	if totalUncompressedLen > 0 {
		gz, err := zlib.NewWriterLevelDict(res, flate.BestCompression, buildZlibDictForEntries(entries, chain))
		if err != nil {
			return nil, fmt.Errorf("cert compression failed: %s", err.Error())
		}

		utils.LittleEndian.WriteUint32(res, uint32(totalUncompressedLen))

		for i, e := range entries {
			if e.t != entryCompressed {
				continue
			}
			lenCert := len(chain[i])
			gz.Write([]byte{
				byte(lenCert & 0xff),
				byte((lenCert >> 8) & 0xff),
				byte((lenCert >> 16) & 0xff),
				byte((lenCert >> 24) & 0xff),
			})
			gz.Write(chain[i])
		}

		gz.Close()
	}

	return res.Bytes(), nil
}

func decompressChain(data []byte) ([][]byte, error) {
	var chain [][]byte
	var entries []entry
	r := bytes.NewReader(data)

	var numCerts int
	var hasCompressedCerts bool
	for {
		entryTypeByte, err := r.ReadByte()
		if entryTypeByte == 0 {
			break
		}

		et := entryType(entryTypeByte)
		if err != nil {
			return nil, err
		}

		numCerts++

		switch et {
		case entryCached:
			// we're not sending any certificate hashes in the CHLO, so there shouldn't be any cached certificates in the chain
			return nil, errors.New("unexpected cached certificate")
		case entryCommon:
			e := entry{t: entryCommon}
			e.h, err = utils.LittleEndian.ReadUint64(r)
			if err != nil {
				return nil, err
			}
			e.i, err = utils.LittleEndian.ReadUint32(r)
			if err != nil {
				return nil, err
			}
			certSet, ok := certSets[e.h]
			if !ok {
				return nil, errors.New("unknown certSet")
			}
			if e.i >= uint32(len(certSet)) {
				return nil, errors.New("certificate not found in certSet")
			}
			entries = append(entries, e)
			chain = append(chain, certSet[e.i])
		case entryCompressed:
			hasCompressedCerts = true
			entries = append(entries, entry{t: entryCompressed})
			chain = append(chain, nil)
		default:
			return nil, errors.New("unknown entryType")
		}
	}

	if numCerts == 0 {
		return make([][]byte, 0), nil
	}

	if hasCompressedCerts {
		uncompressedLength, err := utils.LittleEndian.ReadUint32(r)
		if err != nil {
			fmt.Println(4)
			return nil, err
		}

		zlibDict := buildZlibDictForEntries(entries, chain)
		gz, err := zlib.NewReaderDict(r, zlibDict)
		if err != nil {
			return nil, err
		}
		defer gz.Close()

		var totalLength uint32
		var certIndex int
		for totalLength < uncompressedLength {
			lenBytes := make([]byte, 4)
			_, err := gz.Read(lenBytes)
			if err != nil {
				return nil, err
			}
			certLen := binary.LittleEndian.Uint32(lenBytes)

			cert := make([]byte, certLen)
			n, err := gz.Read(cert)
			if uint32(n) != certLen && err != nil {
				return nil, err
			}

			for {
				if certIndex >= len(entries) {
					return nil, errors.New("CertCompression BUG: no element to save uncompressed certificate")
				}
				if entries[certIndex].t == entryCompressed {
					chain[certIndex] = cert
					certIndex++
					break
				}
				certIndex++
			}

			totalLength += 4 + certLen
		}
	}

	return chain, nil
}

func buildEntries(chain [][]byte, chainHashes, cachedHashes, setHashes []uint64) []entry {
	res := make([]entry, len(chain))
chainLoop:
	for i := range chain {
		// Check if hash is in cachedHashes
		for j := range cachedHashes {
			if chainHashes[i] == cachedHashes[j] {
				res[i] = entry{t: entryCached, h: chainHashes[i]}
				continue chainLoop
			}
		}

		// Go through common sets and check if it's in there
		for _, setHash := range setHashes {
			set, ok := certSets[setHash]
			if !ok {
				// We don't have this set
				continue
			}
			// We have this set, check if chain[i] is in the set
			pos := set.findCertInSet(chain[i])
			if pos >= 0 {
				// Found
				res[i] = entry{t: entryCommon, h: setHash, i: uint32(pos)}
				continue chainLoop
			}
		}

		res[i] = entry{t: entryCompressed}
	}
	return res
}

func buildZlibDictForEntries(entries []entry, chain [][]byte) []byte {
	var dict bytes.Buffer

	// First the cached and common in reverse order
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].t == entryCompressed {
			continue
		}
		dict.Write(chain[i])
	}

	dict.Write(certDictZlib)
	return dict.Bytes()
}

func splitHashes(hashes []byte) ([]uint64, error) {
	if len(hashes)%8 != 0 {
		return nil, errors.New("expected a multiple of 8 bytes for CCS / CCRT hashes")
	}
	n := len(hashes) / 8
	res := make([]uint64, n)
	for i := 0; i < n; i++ {
		res[i] = binary.LittleEndian.Uint64(hashes[i*8 : (i+1)*8])
	}
	return res, nil
}

func getCommonCertificateHashes() []byte {
	ccs := make([]byte, 8*len(certSets))
	i := 0
	for certSetHash := range certSets {
		binary.LittleEndian.PutUint64(ccs[i*8:(i+1)*8], certSetHash)
		i++
	}
	return ccs
}

// HashCert calculates the FNV1a hash of a certificate
func HashCert(cert []byte) uint64 {
	h := fnv.New64a()
	h.Write(cert)
	return h.Sum64()
}
