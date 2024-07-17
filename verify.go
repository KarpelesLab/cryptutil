package cryptutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

// Verify will verify the given buffer against the signature, depending on the key type. If the
// key is a RSA key and PSS options are given, then the signature will be handled as a PSS signature.
func Verify(key crypto.PublicKey, buf, sig []byte, opts ...crypto.SignerOpts) error {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		for _, opt := range opts {
			if opt, ok := opt.(*rsa.PSSOptions); ok {
				hf := opt.Hash
				return rsa.VerifyPSS(pub, hf, Hash(buf, hf.New), sig, opt)
			}
		}
		hf := getHashFunc(opts)
		return rsa.VerifyPKCS1v15(pub, hf, Hash(buf, hf.New), sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, Hash(buf, getHashFunc(opts).New), sig) {
			return ErrVerifyFailed
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, buf, sig) {
			return ErrVerifyFailed
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature key type %T", key)
	}
}

// getHashFunc finds the hash func from the given list, or returns sha256 by default
func getHashFunc(list []crypto.SignerOpts) crypto.Hash {
	for _, v := range list {
		return v.HashFunc()
	}
	return crypto.SHA256
}
