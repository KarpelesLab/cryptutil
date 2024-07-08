package cryptutil

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
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
		priv, err := r.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		sk, err := priv.ECDH(r)
		if err != nil {
			return nil, err
		}
		defer MemClr(sk)
		h := sha256.Sum256(sk)
		defer MemClr(h[:])
		// invoke aes
		bc, err := aes.NewCipher(h[:])
		if err != nil {
			return nil, err
		}
		privB := priv.Bytes()
		bs := bc.BlockSize()
		dst := make([]byte, bs+len(privB)+len(k))
		_, err = io.ReadFull(rand.Reader, dst[:bs])
		if err != nil {
			return nil, err
		}
		copy(dst[bs:bs+len(privB)], privB)
		// encode
		enc := cipher.NewCFBEncrypter(bc, dst[:bs])
		enc.XORKeyStream(dst[bs+len(privB):], k)
		return dst, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", r)
	}
}

// DecryptShortBuffer decrypts a given short buffer
func DecryptShortBuffer(k []byte, rcvd any) ([]byte, error) {
	switch r := rcvd.(type) {
	case ECDHHandler:
		// message is 16 bytes IV (AES blocksize is always 16), ephemeral public key, and data
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
