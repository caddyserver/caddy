package crypto

// KeyExchange manages the exchange of keys
type KeyExchange interface {
	PublicKey() []byte
	CalculateSharedKey(otherPublic []byte) ([]byte, error)
}
