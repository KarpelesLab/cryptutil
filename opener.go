package cryptutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

// Opener allows opening a [Bottle]
type Opener struct {
	kc *Keychain
}

// EmptyOpener is an opener without any keys that can open bottles, but can't check keys
var EmptyOpener = &Opener{}

type OpenResult struct {
	Decryption int                 // number of performed decryptions
	Signatures []*MessageSignature // verified message signatures
	Bottles    []*Bottle
}

// Last returns the last (inside-most) bottle, which will contain any relevant meta-data
func (or *OpenResult) Last() *Bottle {
	if len(or.Bottles) == 0 {
		// should never happen
		panic("OpenResult has no bottles")
	}
	return or.Bottles[len(or.Bottles)-1]
}

// First returns the first (outside-most) bottle, that will be what has been passed to Open
func (or *OpenResult) First() *Bottle {
	if len(or.Bottles) == 0 {
		// should never happen
		panic("OpenResult has no bottles")
	}
	return or.Bottles[0]
}

// NewOpener returns an opener that can be used to open a [Bottle] using any or all of the given keys.
func NewOpener(keys ...any) (*Opener, error) {
	res := &Opener{kc: NewKeychain()}
	for _, k := range keys {
		if err := res.kc.AddKey(k); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// MustOpener returns an opener that can be used to open a [Bottle] and panics if it fails
func MustOpener(keys ...any) *Opener {
	op, err := NewOpener(keys...)
	if err != nil {
		panic(err)
	}
	return op
}

func (o *Opener) addKey(k any) error {
	return o.kc.AddKey(k)
}

// UnmarshalJson will open the given json-encoded bottle and pour the contents into v
func (o *Opener) UnmarshalJson(b []byte, v any) (*OpenResult, error) {
	return o.Unmarshal(AsJsonBottle(b), v)
}

// UnmarshalCbor will open the given cbor-encoded bottle and pour the contents into v
func (o *Opener) UnmarshalCbor(b []byte, v any) (*OpenResult, error) {
	return o.Unmarshal(AsCborBottle(b), v)
}

// Unmarshal will open the given bottle and pour the contents into v
func (o *Opener) Unmarshal(b *Bottle, v any) (*OpenResult, error) {
	buf, res, err := o.Open(b)
	if err != nil {
		return res, err
	}
	ct, ok := res.Last().Header["ct"]
	if !ok {
		ct = "cbor" // default
	}
	switch ct {
	case "cbor":
		err = cbor.Unmarshal(buf, v)
		return res, err
	case "json":
		err = json.Unmarshal(buf, v)
		return res, err
	default:
		return res, fmt.Errorf("unsupported content type %s", ct)
	}
}

// UnmarshalHttp will read the data from a [http.Request] and unmarshal it into v.
func (o *Opener) UnmarshalHttp(req *http.Request, v any) (*OpenResult, error) {
	b, err := httpToBottle(req)
	if err != nil {
		return nil, err
	}
	return o.Unmarshal(b, v)
}

// OpenCbor opens the given [Bottle] encoded as cbor data.
func (o *Opener) OpenCbor(b []byte) ([]byte, *OpenResult, error) {
	return o.Open(AsCborBottle(b))
}

// OpenJson opens the given [Bottle] encoded as json data.
func (o *Opener) OpenJson(b []byte) ([]byte, *OpenResult, error) {
	return o.Open(AsJsonBottle(b))
}

func httpToBottle(req *http.Request) (*Bottle, error) {
	ct, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("malformed Content-Type header: %w", err)
	}
	switch ct {
	case "application/json":
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		return AsJsonBottle(data), nil
	case "application/cbor":
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		return AsCborBottle(data), nil
	default:
		return nil, fmt.Errorf("unsupported data mime type %s", ct)
	}
}

// OpenHttp will read the data from a [http.Request] handling the content-type header.
func (o *Opener) OpenHttp(req *http.Request) ([]byte, *OpenResult, error) {
	b, err := httpToBottle(req)
	if err != nil {
		return nil, nil, err
	}
	return o.Open(b)
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
		case JsonBottle:
			var nb *Bottle
			err := json.Unmarshal(b.Message, &nb)
			if err != nil {
				return nil, res, err
			}
			b = nb
		case AES:
			if o.kc == nil {
				return nil, res, ErrNoAppropriateKey
			}
			var k []byte
			finalErr := ErrNoAppropriateKey
			for _, sub := range b.Recipients {
				decKey, err := o.kc.GetKey(sub.Recipient)
				if err == nil {
					buf, err := sub.OpenWith(decKey)
					if err == nil {
						k = buf
						break
					} else {
						finalErr = err
					}
				}
			}
			if k == nil {
				return nil, res, finalErr
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

// SignedBy returns true if the message was signed by the signer (either a public key or a [IDCard])
func (or *OpenResult) SignedBy(signer any) bool {
	switch v := signer.(type) {
	case *IDCard:
		keys := v.GetKeys("sign")
		for _, k := range keys {
			if or.SignedBy(k) {
				return true
			}
		}
		return false
	default:
		bin, err := x509.MarshalPKIXPublicKey(signer)
		if err != nil {
			return false
		}
		// find bin in or.Signatures
		for _, sig := range or.Signatures {
			if bytes.Equal(sig.Signer, bin) {
				return true
			}
		}
		return false
	}
}
