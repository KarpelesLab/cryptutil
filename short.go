package cryptutil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
)

// EncryptShortBuffer performs a simple encryption of a buffer
func EncryptShortBuffer(rand io.Reader, k []byte, rcvd crypto.PublicKey) ([]byte, error) {
	switch r := rcvd.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand, r, k, nil)
	case *ecdsa.PublicKey:
		nr, err := r.ECDH()
		if err != nil {
			return nil, err
		}
		return EncryptShortBuffer(rand, k, nr)
	case ed25519.PublicKey:
		nr, err := ecdh.X25519().NewPublicKey(r[:])
		if err != nil {
			return nil, err
		}
		return EncryptShortBuffer(rand, k, nr)
	case *ecdh.PublicKey:
		return ECDHEncrypt(rand, k, r)
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
			return r.Decrypt(nil, k, &rsa.OAEPOptions{Hash: crypto.SHA256})
		default:
			return r.Decrypt(nil, k, nil)
		}
	case ed25519.PrivateKey:
		pk, err := ecdh.X25519().NewPrivateKey(r)
		if err != nil {
			return nil, err
		}
		return DecryptShortBuffer(k, pk)
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
