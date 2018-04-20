/*-
 * Copyright 2017 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"os"

	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/square/go-jose.v2"
)

var (
	app = kingpin.New("jwk-keygen", "A command-line utility to generate public/pirvate keypairs in JWK format.")

	use = app.Flag("use", "Desrired key use").Required().Enum("enc", "sig")
	alg = app.Flag("alg", "Generate key to be used for ALG").Required().Enum(
		// `sig`
		string(jose.ES256), string(jose.ES384), string(jose.ES512), string(jose.EdDSA),
		string(jose.RS256), string(jose.RS384), string(jose.RS512), string(jose.PS256), string(jose.PS384), string(jose.PS512),
		// `enc`
		string(jose.RSA1_5), string(jose.RSA_OAEP), string(jose.RSA_OAEP_256),
		string(jose.ECDH_ES), string(jose.ECDH_ES_A128KW), string(jose.ECDH_ES_A192KW), string(jose.ECDH_ES_A256KW),
	)
	bits    = app.Flag("bits", "Key size in bits").Int()
	kid     = app.Flag("kid", "Key ID").String()
	kidRand = app.Flag("kid-rand", "Generate random Key ID").Bool()
)

// KeygenSig generates keypair for corresponding SignatureAlgorithm.
func KeygenSig(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // sic!
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("this `alg` does not support arbitrary key length")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
	}
	switch alg {
	case jose.ES256:
		// The cryptographic operations are implemented using constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key.Public(), key, err
	case jose.ES384:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return key.Public(), key, err
	case jose.ES512:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `sig`")
	}
}

// KeygenEnc generates keypair for corresponding KeyAlgorithm.
func KeygenEnc(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("unknown elliptic curve bit length, use one of 256, 384, 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `enc`")
	}
}

func main() {
	app.Version("v2")
	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *kidRand {
		if *kid == "" {
			b := make([]byte, 5)
			_, err := rand.Read(b)
			app.FatalIfError(err, "can't Read() crypto/rand")
			*kid = base32.StdEncoding.EncodeToString(b)
		} else {
			app.FatalUsage("can't combine --kid and --kid-rand")
		}
	}

	var privKey crypto.PublicKey
	var pubKey crypto.PrivateKey
	var err error
	switch *use {
	case "sig":
		pubKey, privKey, err = KeygenSig(jose.SignatureAlgorithm(*alg), *bits)
	case "enc":
		pubKey, privKey, err = KeygenEnc(jose.KeyAlgorithm(*alg), *bits)
	}
	app.FatalIfError(err, "unable to generate key")

	priv := jose.JSONWebKey{Key: privKey, KeyID: *kid, Algorithm: *alg, Use: *use}
	pub := jose.JSONWebKey{Key: pubKey, KeyID: *kid, Algorithm: *alg, Use: *use}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		app.Fatalf("invalid keys were generated")
	}

	privJS, err := priv.MarshalJSON()
	app.FatalIfError(err, "can't Marshal private key to JSON")
	pubJS, err := pub.MarshalJSON()
	app.FatalIfError(err, "can't Marshal public key to JSON")

	if *kid == "" {
		fmt.Printf("==> jwk_%s.pub <==\n", *alg)
		fmt.Println(string(pubJS))
		fmt.Printf("==> jwk_%s <==\n", *alg)
		fmt.Println(string(privJS))
	} else {
		// JWK Thumbprint (RFC7638) is not used for key id because of
		// lack of canonical representation.
		fname := fmt.Sprintf("jwk_%s_%s_%s", *use, *alg, *kid)
		err = writeNewFile(fname+".pub", pubJS, 0444)
		app.FatalIfError(err, "can't write public key to file %s.pub", fname)
		fmt.Printf("Written public key to %s.pub\n", fname)
		err = writeNewFile(fname, privJS, 0400)
		app.FatalIfError(err, "cant' write private key to file %s", fname)
		fmt.Printf("Written private key to %s\n", fname)
	}
}

// writeNewFile is shameless copy-paste from ioutil.WriteFile with a bit
// different flags for OpenFile.
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
