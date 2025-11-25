package cryptutil

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Membership is a membership in a group.
type Membership struct {
	Subject   []byte            `json:"sub" cbor:"1,keyasint"` // must be == parent.Self (if empty, fill with parent.Self before sig)
	Key       []byte            `json:"key" cbor:"2,keyasint"` // group key (group identification)
	Status    string            `json:"sta" cbor:"3,keyasint"` // status of membership (valid|suspended)
	Issued    time.Time         `json:"iss" cbor:"4,keyasint"` // update time of membership info
	Info      map[string]string `json:"nfo" cbor:"5,keyasint"` // subject information (name, etc)
	SignKey   []byte            `json:"sky" cbor:"6,keyasint"` // signature generating key (must be listed as sign key for the Key's IDCard)
	Signature []byte            `json:"sig" cbor:"7,keyasint"` // signature of structure with sign=nil by group key
}

func NewMembership(member *IDCard, key []byte) *Membership {
	res := &Membership{
		Subject: member.Self,
		Key:     key,
		Status:  "valid",
		Issued:  time.Now(),
		Info:    make(map[string]string),
	}

	return res
}

// SignatureBytes returns a representation of Membership that can be used to sign or verify the structure
func (m *Membership) SignatureBytes() ([]byte, error) {
	cp := &Membership{
		Subject:   m.Subject,
		Key:       m.Key,
		Status:    m.Status,
		Issued:    m.Issued,
		Info:      m.Info,
		SignKey:   m.SignKey,
		Signature: nil,
	}

	// generate cbor representation using canonical mode
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(cp)
}

// Sign signs the membership using the provided key
func (m *Membership) Sign(rand io.Reader, key crypto.Signer, opts ...crypto.SignerOpts) error {
	if m.Subject == nil {
		return errors.New("Subject must be filled prior to signing or verifying a Membership")
	}

	pub := key.Public()
	pubBin, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	m.SignKey = pubBin

	buf, err := m.SignatureBytes()
	if err != nil {
		return err
	}

	sig, err := Sign(rand, key, buf, opts...)
	if err != nil {
		return err
	}

	m.Signature = sig

	return nil
}

// Verify ensures the signature is correct. If the group ID is known, it must be passed.
func (m *Membership) Verify(groupId *IDCard) error {
	if m.Subject == nil {
		return errors.New("Subject must be filled prior to signing or verifying a Membership")
	}
	k, err := ParsePKIXPublicKey(m.SignKey)
	if err != nil {
		return err
	}
	if groupId == nil {
		// This equal check must be done only if id is nil
		if !bytes.Equal(m.SignKey, m.Key) {
			return errors.New("invalid signing key")
		}
	} else {
		if !bytes.Equal(m.Key, groupId.Self) {
			return errors.New("Invalid ID for group verification")
		}
		if err := groupId.TestKeyPurpose(k, "sign"); err != nil {
			return fmt.Errorf("invalid signing key: %w", err)
		}
	}
	sigB, err := m.SignatureBytes()
	if err != nil {
		return err
	}

	return Verify(k, sigB, m.Signature, crypto.SHA256)
}
