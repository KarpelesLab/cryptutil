package cryptutil

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor"
)

// Opener allows opening a [Bottle]
type Opener struct {
	keys map[[32]byte]any
}

type OpenResult struct {
	Decryption int                 // number of performed decryptions
	Signatures []*MessageSignature // verified message signatures
	Bottles    []*Bottle
}

func NewOpener(keys ...any) (*Opener, error) {
	res := &Opener{keys: make(map[[32]byte]any)}
	for _, k := range keys {
		if err := res.addKey(k); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (o *Opener) addKey(k any) error {
	ki, ok := k.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("unsupported key type %T", k)
	}
	pub, err := x509.MarshalPKIXPublicKey(ki.Public())
	if err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}
	// we could also use string(pub), but having a string of non utf-8 data isn't something I like
	o.keys[sha256.Sum256(pub)] = k
	return nil
}

// Open opens the given [Bottle], decrypting any encrypted elements, checking all signatures and returning the embedded buffer in the end
func (o *Opener) Open(b *Bottle) ([]byte, *OpenResult, error) {
	res := &OpenResult{}

	for {
		res.Bottles = append(res.Bottles, b)

		for _, sig := range b.Signatures {
			err := sig.Verify(b.Message)
			if err != nil {
				return nil, res, err
			}
			res.Signatures = append(res.Signatures, sig)
		}

		switch b.Format {
		case ClearText:
			return b.Message, res, nil
		case CborBottle:
			var nb *Bottle
			err := cbor.Unmarshal(b.Message, &nb)
			if err != nil {
				return nil, res, err
			}
			b = nb
		case AES:
			var k []byte
			for _, sub := range b.Recipients {
				decKey, ok := o.keys[sha256.Sum256(sub.Recipient)]
				if ok {
					buf, err := sub.OpenWith(decKey)
					if err == nil {
						k = buf
						break
					}
				}
			}
			if k == nil {
				return nil, res, errors.New("no appropriate key available to open bottle")
			}
			defer MemClr(k)

			bc, err := aes.NewCipher(k)
			if err != nil {
				return nil, res, err
			}

			gcm, err := cipher.NewGCM(bc)
			if err != nil {
				return nil, res, err
			}

			nonce := b.Message[:gcm.NonceSize()]
			buf, err := gcm.Open(nil, nonce, b.Message[gcm.NonceSize():], nil)
			if err != nil {
				return nil, res, err
			}

			res.Decryption += 1

			var nb *Bottle
			err = cbor.Unmarshal(buf, &nb)
			if err != nil {
				return nil, res, err
			}
			b = nb
		}
	}
}