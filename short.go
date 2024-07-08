package cryptutil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// EncryptShortBuffer performs a simple encryption of a buffer
func EncryptShortBuffer(k []byte, rcvd crypto.PublicKey) ([]byte, error) {
	switch r := rcvd.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, r, k, nil)
	case *ecdsa.PublicKey:
		nr, err := r.ECDH()
		if err != nil {
			return nil, err
		}
		return EncryptShortBuffer(k, nr)
	case ed25519.PublicKey:
		nr, err := ecdh.X25519().NewPublicKey(r[:])
		if err != nil {
			return nil, err
		}
		return EncryptShortBuffer(k, nr)
	case *ecdh.PublicKey:
		return ECDHEncrypt(k, r, rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type %T", r)
	}
}

// DecryptShortBuffer decrypts a given buffer
func DecryptShortBuffer(k []byte, rcvd any) ([]byte, error) {
	switch r := rcvd.(type) {
	case ECDHHandler:
		return ECDHDecrypt(k, r)
	case crypto.Decrypter:
		switch r.Public().(type) {
		case *rsa.PublicKey:
			return r.Decrypt(rand.Reader, k, &rsa.OAEPOptions{Hash: crypto.SHA256})
		default:
			return r.Decrypt(rand.Reader, k, nil)
		}
	case interface {
		ECDH() (*ecdh.PrivateKey, error)
	}:
		pk, err := r.ECDH()
		if err != nil {
			return nil, err
		}
		return DecryptShortBuffer(k, pk)
	default:
		return nil, fmt.Errorf("unsupported key type %T", r)
	}
}
