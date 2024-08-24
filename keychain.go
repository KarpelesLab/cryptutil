package cryptutil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

type privateKey interface {
	Public() crypto.PublicKey
}

// Keychain is an object storing private keys that can be used to sign or decrypt things.
type Keychain struct {
	keys map[string]privateKey
}

// NewKeychain returns a new, empty keychain
func NewKeychain() *Keychain {
	return &Keychain{keys: make(map[string]privateKey)}
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
// object that can be marshalled by [crypto/x509.MarshalPKIXPublicKey].
func (kc *Keychain) AddKey(k any) error {
	ki, ok := k.(privateKey)
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

func (kc *Keychain) AsSubKeys() (res []*SubKey) {
	now := time.Now()

	for _, sk := range kc.keys {
		pub := sk.Public()
		pubBin, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			continue
		}
		subKey := &SubKey{
			Key:      pubBin,
			Issued:   now,
			Purposes: guessPurposes(pub),
		}
		res = append(res, subKey)
	}
	return
}

func guessPurposes(pub crypto.PublicKey) []string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return []string{"sign", "decrypt"}
	case *ecdsa.PublicKey:
		return []string{"sign", "decrypt"}
	case ed25519.PublicKey:
		// ed25519 keys can't be used as is for encryption
		return []string{"sign"}
	case *ecdh.PublicKey:
		return []string{"decrypt"}
	default:
		return nil
	}
}
