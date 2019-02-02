package registration

import (
	"crypto"
)

// User interface is to be implemented by users of this library.
// It is used by the client type to get user specific information.
type User interface {
	GetEmail() string
	GetRegistration() *Resource
	GetPrivateKey() crypto.PrivateKey
}
