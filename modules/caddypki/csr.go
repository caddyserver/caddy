package caddypki

import (
	"encoding/json"
	"fmt"
)

// The key type to be used for signing the CSR. The possible types are:
// EC, RSA, and OKP.
type keyType string

const (
	keyTypeEC  keyType = "EC"
	keyTypeRSA keyType = "RSA"
	keyTypeOKP keyType = "OKP"
)

var stringToKey = map[string]keyType{
	"EC":  keyTypeEC,
	"RSA": keyTypeRSA,
	"OKP": keyTypeOKP,
}

func (kt *keyType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case string(keyTypeEC), string(keyTypeRSA), string(keyTypeOKP):
		*kt = stringToKey[s]
	default:
		return fmt.Errorf("unknown key type: %s", s)
	}
	return nil
}

func (kt keyType) String() string {
	return string(kt)
}

// The curve to use with key types EC and OKP.
// If the Type is OKP, then acceptable curves are: Ed25519, or X25519
// If the Type is EC, then acceptable curves are: P-256, P-384, or P-521
type curve string

const (
	curveEd25519 curve = "Ed25519"
	curveX25519  curve = "X25519"
	curveP256    curve = "P-256"
	curveP384    curve = "P-384"
	curveP521    curve = "P-521"
)

var stringToCurve = map[string]curve{
	"Ed25519": curveEd25519,
	"X25519":  curveX25519,
	"P-256":   curveP256,
	"P-384":   curveP384,
	"P-521":   curveP521,
}

func (c *curve) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case string(curveEd25519), string(curveX25519), string(curveP256), string(curveP384), string(curveP521):
		*c = stringToCurve[s]
	default:
		return fmt.Errorf("unknown curve: %s", s)
	}
	return nil
}

func (c curve) String() string {
	return string(c)
}

type keyParameters struct {
	// The key type to be used for signing the CSR. The possible types are:
	// EC, RSA, and OKP.
	// The value of this field is case-sensitive.
	Type keyType `json:"type"`

	// The curve to use with key types EC and OKP.
	// If the Type is OKP, then acceptable curves are: Ed25519, or X25519
	// If the Type is EC, then acceptable curves are: P-256, P-384, or P-521
	// The value of this field is case-sensitive.
	Curve curve `json:"curve,omitempty"`

	// Only used with RSA keys and accepts minimum of 2048.
	Size int `json:"size,omitempty"`
}

func (kp *keyParameters) validate() error {
	if kp == nil {
		return nil
	}

	if kp.Type == keyTypeRSA {
		if kp.Size < 2048 {
			return fmt.Errorf("minimum RSA key size is 2048 bits: %v", kp.Size)
		}
	}
	if kp.Type == keyTypeEC {
		switch kp.Curve {
		case curveP256, curveP384, curveP521:
			return nil
		default:
			return fmt.Errorf("unrecognized EC curve: %v", kp.Curve)
		}
	}
	if kp.Type == keyTypeOKP {
		switch kp.Curve {
		case curveEd25519, curveX25519:
			return nil
		default:
			return fmt.Errorf("unrecognized OKP curve: %v", kp.Curve)
		}
	}
	return nil
}

type csrRequest struct {
	// Custom name assigned to the CSR key. If empty, UUID is generated and assigned.
	ID string `json:"id,omitempty"`

	// Customization knobs of the generated/loaded key, if desired. The format is:
	// {
	//		// Valid values for type are: EC, RSA, and OKP.
	// 	 	"type": "",
	//
	//  	// The curve to use with key types EC and OKP.
	//  	// If the Type is OKP, then acceptable curves are: Ed25519, or X25519
	//  	// If the Type is EC, then acceptable curves are: P-256, P-384, or P-521
	// 	 	"curve": "",
	//
	//  	// Only used with RSA keys and accepts minimum of 2048.
	// 	 	"size": 0
	// }
	//
	// If empty, sane defaults will be managed internally without exposing their details
	// to the user. At the moment, the default parameters are:
	// {
	// 	 	"type": "EC",
	// 	 	"curve": "P-256"
	// }
	// The values are case-sensitive.
	Key *keyParameters `json:"key,omitempty"`

	// SANs is a list of subject alternative names for the certificate.
	SANs []string `json:"sans"`
}

func (c csrRequest) validate() error {
	return c.Key.validate()
}
