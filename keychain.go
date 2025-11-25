package cryptutil

import (
	"crypto"
	"fmt"
	"io"
)

// Keychain is an object storing private keys that can be used to sign or decrypt things.
type Keychain struct {
	keys    map[string]PrivateKey
	signKey crypto.Signer
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
// object that can be marshalled by [crypto/x509.MarshalPKIXPublicKey], or an [MLKEMPrivateKey]. If another [Keychain]
// is passed all its keys will be added.
func (kc *Keychain) AddKey(k any) error {
	// Handle ML-KEM keys specially - use PKIX encoding
	if mlkemKey, ok := k.(*MLKEMPrivateKey); ok {
		pub, err := mlkemKey.MLKEMPublic().MarshalPKIXPublicKey()
		if err != nil {
			return fmt.Errorf("failed to marshal ML-KEM public key: %w", err)
		}
		kc.keys[string(pub)] = mlkemKey
		return nil
	}

	ki, ok := k.(PrivateKey)
	if !ok {
		if kc2, ok := k.(*Keychain); ok {
			// add keys from a separate keychain
			for subk, subv := range kc2.keys {
				kc.keys[subk] = subv
			}
			if kc.signKey == nil {
				kc.signKey = kc2.signKey
			}
			return nil
		}
		return fmt.Errorf("unsupported key type %T", k)
	}
	pub, err := MarshalPKIXPublicKey(ki.Public())
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	kc.keys[string(pub)] = ki

	// if this is a signing key, set kc.signKey
	if kc.signKey == nil {
		if sig, ok := ki.(crypto.Signer); ok {
			kc.signKey = sig
		}
	}

	return nil
}

// GetKey returns the private key matching the passed public key, if known. A []byte of the PKIX marshalled public key,
// a public key object, or an [MLKEMPublicKey] can be passed.
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
	case *MLKEMPublicKey:
		buf, err := p.MarshalPKIXPublicKey()
		if err != nil {
			return nil, err
		}
		if v, ok := kc.keys[string(buf)]; ok {
			return v, nil
		}
		return nil, ErrKeyNotFound
	default:
		buf, err := MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		if v, ok := kc.keys[string(buf)]; ok {
			return v, nil
		}
		return nil, fmt.Errorf("%w or public key type %T not supported", ErrKeyNotFound, public)
	}
}

// FirstSigner returns the first [crypto.Signer] that was added to this [Keychain].
func (kc *Keychain) FirstSigner() crypto.Signer {
	return kc.signKey
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

// All returns all the keys in the Keychain
func (kc *Keychain) All(yield func(PrivateKey) bool) {
	for _, key := range kc.keys {
		if !yield(key) {
			return
		}
	}
}

// Signers returns all the signing-capable keys in the Keychain
func (kc *Keychain) Signers(yield func(crypto.Signer) bool) {
	for _, key := range kc.keys {
		if signer, ok := key.(crypto.Signer); ok {
			if !yield(signer) {
				return
			}
		}
	}
}
