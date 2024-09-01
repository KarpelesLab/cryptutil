package cryptutil

import "crypto"

// PrivateKey represents a private key using an unspecified algorithm.
//
// All private keys must implement a method to retrieve the matching public key.
type PrivateKey interface {
	Public() crypto.PublicKey
}

// PublicKey returns the public key for a given private key, or nil if the argumlent is not a private
// key or if its Public() method returned nil.
func PublicKey(privKey crypto.PrivateKey) crypto.PublicKey {
	if v, ok := privKey.(interface{ Public() crypto.PublicKey }); ok {
		return v.Public()
	}
	return nil
}
