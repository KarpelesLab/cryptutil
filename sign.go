package cryptutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// Sign generates a signature for the given buffer. Hash will be performed as needed
func Sign(key crypto.Signer, buf []byte, opts ...crypto.SignerOpts) ([]byte, error) {
	pub := key.Public()
	switch pub.(type) {
	case *rsa.PublicKey:
		if opt := getSignerOpt[rsa.PSSOptions](opts); opt != nil {
			return key.Sign(rand.Reader, Hash(buf, opt.Hash.New), opt)
		}
		hf := getHashFunc(opts)
		return key.Sign(rand.Reader, Hash(buf, hf.New), hf)
	case ed25519.PublicKey:
		if opt := getSignerOpt[ed25519.Options](opts); opt != nil {
			if opt.Hash == crypto.SHA512 {
				buf = Hash(buf, crypto.SHA512.New)
			}
			return key.Sign(rand.Reader, buf, opt)
		}
		hf := getHashFunc(opts)
		if hf == crypto.SHA512 {
			return key.Sign(rand.Reader, Hash(buf, hf.New), hf)
		}
		return key.Sign(rand.Reader, buf, crypto.Hash(0))
	default:
		hf := getHashFunc(opts)
		return key.Sign(rand.Reader, Hash(buf, hf.New), hf)
	}
}

// Verify will verify the given buffer against the signature, depending on the key type. If the
// key is a RSA key and PSS options are given, then the signature will be handled as a PSS signature.
//
// Unlike Verify methods found in most packages, this one takes in the actual buffer to be signed
// and will perform the hash if it needs to be done.
func Verify(key crypto.PublicKey, buf, sig []byte, opts ...crypto.SignerOpts) error {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		for _, opt := range opts {
			if opt, ok := opt.(*rsa.PSSOptions); ok {
				return rsa.VerifyPSS(pub, opt.Hash, Hash(buf, opt.Hash.New), sig, opt)
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
		if opt := getSignerOpt[ed25519.Options](opts); opt != nil {
			if opt.Hash == crypto.SHA512 {
				buf = Hash(buf, crypto.SHA512.New)
			}
			return ed25519.VerifyWithOptions(pub, buf, sig, opt)
		}
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

func getSignerOpt[T any](list []crypto.SignerOpts) *T {
	for _, v := range list {
		if res, ok := any(v).(*T); ok {
			return res
		}
	}
	return nil
}
