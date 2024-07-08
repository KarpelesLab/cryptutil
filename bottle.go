package cryptutil

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type MessageFormat int

const (
	ClearText  MessageFormat = iota
	CborBottle               // bottle in a bottle
	AES                      // AES+AEAD encrypted bottle
)

// Bottle is a signed, encrypted message container. Any Format other than ClearText means the Message contains
// a Bottle that has been encrypted.
type Bottle struct {
	_          struct{}            `cbor:",toarray"`
	Header     map[string]any      `json:"hdr,omitempty"` // extra values to be stored, will not be signed/encrypted unless the message is bottled
	Message    []byte              `json:"msg"`
	Format     MessageFormat       `json:"fmt"`
	Recipients []*MessageRecipient `json:"dst,omitempty"` // if Format != ClearText
	Signatures []*MessageSignature `json:"sig,omitempty"` // signature

}

type MessageRecipient struct {
	_         struct{} `cbor:",toarray"`
	Type      int      `json:"typ"` // always 0 (for now)
	Recipient []byte   `json:"key"` // recipient's public key
	Data      []byte   `json:"dat"` // encrypted key payload (only recipient's eyes)
}

type MessageSignature struct {
	_      struct{} `cbor:",toarray"`
	Type   int      `json:"typ"` // always 0 (for now)
	Signer []byte   `json:"key"` // signature's key
	Data   []byte   `json:"dat"` // signature payload, similar format to jwt (NOTE: ECDSA signatures are weird)
}

func NewBottle(data []byte) *Bottle {
	return &Bottle{Format: ClearText, Message: data, Header: make(map[string]any)}
}

// BottleUp encodes the current message into itself, allowing application of extra layers
func (m *Bottle) BottleUp() error {
	// move Bottle into a bottle
	e, err := cbor.Marshal(m)
	if err != nil {
		return err
	}

	// reset
	m.Header = make(map[string]any)
	m.Message = e
	m.Format = CborBottle
	m.Recipients = nil
	m.Signatures = nil

	return nil
}

// IsCleanBottle returns true if the Bottle is clean (ie. so signature has been
// scribbed on top) and contains another Bottle.
func (m *Bottle) IsCleanBottle() bool {
	return m.Format == CborBottle && len(m.Signatures) == 0
}

// Encrypt encrypts the message so only recipients can decrypt it
func (m *Bottle) Encrypt(recipients ...crypto.PublicKey) error {
	// first, make sure we're dealing with a clean bottle
	if !m.IsCleanBottle() {
		err := m.BottleUp()
		if err != nil {
			return err
		}
	}
	// encrypt Buffer with a randomly generated key
	k := make([]byte, 32)
	defer MemClr(k)
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return err
	}

	bc, err := aes.NewCipher(k)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(bc)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}
	newBuf := gcm.Seal(nil, nonce, m.Message, nil)

	// now that we're ready to encrypt, store k encrypted for each recipient
	var final []*MessageRecipient
	for _, r := range recipients {
		buf, err := EncryptShortBuffer(k, r)
		if err != nil {
			return err
		}

		rBin, err := x509.MarshalPKIXPublicKey(r)
		if err != nil {
			return err
		}

		r := &MessageRecipient{
			Recipient: rBin,
			Data:      buf,
		}
		final = append(final, r)
	}

	// set newly encrypted message
	m.Message = append(nonce, newBuf...)
	m.Format = AES
	m.Recipients = final

	return nil
}

// Sign signs the message, and can be called multiple times. Any message can be signed, including a
// raw message. It is however recommanded to bottle up an encrypted message before signing in order
// to ensure the encryption information is signed too.
//
// Attempting to apply encryption to a message with a signature will always cause it to be bottled up
func (m *Bottle) Sign(key crypto.Signer) error {
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	sig, err := key.Sign(rand.Reader, m.Message, nil)
	if err != nil {
		return err
	}
	s := &MessageSignature{
		Signer: pub,
		Data:   sig,
	}
	m.Signatures = append(m.Signatures, s)
	return nil
}
