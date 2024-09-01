package cryptutil

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/x509"
	"fmt"
	"io"
)

// Keychain is an object storing private keys that can be used to sign or decrypt things.
type Keychain struct {
	keys map[string]PrivateKey
}

// NewKeychain returns a new, empty keychain
func NewKeychain() *Keychain {
	return &Keychain{keys: make(map[string]PrivateKey)}
}

// AddKeys adds a number of keys to the keychain, and stops at the first error found.
func (kc *Keychain) AddKeys(keys ...any) error {
	for _, k := range keys {
		if err := kc.AddKey(k); err != nil {
			return err
		}
	}
	return nil
}

// AddKey adds a key to the keychain. The value passed must be a PrivateKey whose Public() method returns a public key
// object that can be marshalled by [crypto/x509.MarshalPKIXPublicKey]. If another [Keychain] is passed all its keys
// will be added.
func (kc *Keychain) AddKey(k any) error {
	ki, ok := k.(PrivateKey)
	if !ok {
		if kc2, ok := k.(*Keychain); ok {
			// add keys from a separate keychain
			for subk, subv := range kc2.keys {
				kc.keys[subk] = subv
			}
			return nil
		}
		return fmt.Errorf("unsupported key type %T", k)
	}
	pub, err := x509.MarshalPKIXPublicKey(ki.Public())
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	kc.keys[string(pub)] = ki

	if ecdhPubProv, ok := k.(interface {
		ECDHPublic() (*ecdh.PublicKey, error)
	}); ok {
		// the private key has a ECDHPublic() method that will return a different key
		ecdhPub, err := ecdhPubProv.ECDHPublic()
		if err == nil {
			pub2, err := x509.MarshalPKIXPublicKey(ecdhPub)
			if err == nil && !bytes.Equal(pub, pub2) {
				kc.keys[string(pub2)] = ki
			}
		}
	}
	return nil
}

// GetKey returns the private key matching the passed public key, if known. A []byte of the PKIX marshalled public key
// or a public key object can be passed.
func (kc *Keychain) GetKey(public any) (PrivateKey, error) {
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

// GetSigner will return the signer matching the public key
func (kc *Keychain) GetSigner(public any) (crypto.Signer, error) {
	k, err := kc.GetKey(public)
	if err != nil {
		return nil, err
	}
	if s, ok := k.(crypto.Signer); ok {
		return s, nil
	}
	return nil, fmt.Errorf("could not make a crypto.Signer of type %T", k)
}

// Sign will use the specified key from the keychain to sign the given buffer. Unlike Go's standard sign method, the
// whole buffer should be passed and will be signed as needed.
func (kc *Keychain) Sign(rand io.Reader, publicKey any, buf []byte, opts ...crypto.SignerOpts) ([]byte, error) {
	k, err := kc.GetSigner(publicKey)
	if err != nil {
		return nil, err
	}
	return Sign(rand, k, buf, opts...)
}
