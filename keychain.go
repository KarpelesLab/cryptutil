package cryptutil

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// Keychain is an object storing private keys that can be used to sign or decrypt things.
type Keychain struct {
	keys map[string]any
}

// NewKeychain returns a new, empty keychain
func NewKeychain() *Keychain {
	return &Keychain{keys: make(map[string]any)}
}

// AddKey adds a key to the keychain. The value passed must be a PrivateKey whose Public() method returns a public key
// object that can be marshalled by [crypto/x509.MarshalPKIXPublicKey].
func (kc *Keychain) AddKey(k any) error {
	ki, ok := k.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("unsupported key type %T", k)
	}
	pub, err := x509.MarshalPKIXPublicKey(ki.Public())
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	kc.keys[string(pub)] = k
	return nil
}

// GetKey returns the private key matching the passed public key, if known. A []byte of the PKIX marshalled public key
// or a public key object can be passed.
func (kc *Keychain) GetKey(public any) (any, error) {
	if kc == nil {
		return nil, ErrKeyNotFound
	}

	switch p := public.(type) {
	case []byte:
		if v, ok := kc.keys[string(p)]; ok {
			return v, nil
		}
		return nil, ErrKeyNotFound
	default:
		buf, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		if v, ok := kc.keys[string(buf)]; ok {
			return v, nil
		}
		return nil, fmt.Errorf("%w or public key type %T not supported", ErrKeyNotFound, public)
	}
}
