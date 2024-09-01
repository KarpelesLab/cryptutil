package cryptutil

import "crypto"

// PrivateKey represents a private key using an unspecified algorithm.
//
// All private keys must implement a method to retrieve the matching public key. The ones in the standard
// lbirary do.
type PrivateKey interface {
	Public() crypto.PublicKey
}

// PublicKeyIntf represents a public key using an unspecified algorithm.
//
// all public key types in the standard library implement this interface
type PublicKeyIntf interface {
	Equal(x crypto.PublicKey) bool
}

// PublicKey returns the public key for a given private key, or nil if the argumlent is not a private
// key or if its Public() method returned nil.
func PublicKey(privKey crypto.PrivateKey) PublicKeyIntf {
	if v, ok := privKey.(PrivateKey); ok {
		if pub, ok := v.Public().(PublicKeyIntf); ok {
			return pub
		}
	}
	return nil
}
