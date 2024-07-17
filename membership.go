package cryptutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
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

func (m *Membership) Sign(key crypto.Signer) error {
	if m.Subject == nil {
		return errors.New("Subject must be filled prior to signing or verifying a Membership")
	}

	pub := key.Public()
	pubBin, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}

	// make a copy for signature
	cp := &Membership{}
	*cp = *m
	cp.SignKey = pubBin
	cp.Signature = nil
	// generate cbor representation
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return err
	}
	buf, err := em.Marshal(cp)
	if err != nil {
		return err
	}

	var sig []byte
	switch pub.(type) {
	case ed25519.PublicKey:
		sig, err = key.Sign(rand.Reader, buf, crypto.Hash(0))
	default:
		sig, err = key.Sign(rand.Reader, Hash(buf, sha256.New), crypto.SHA256)
	}
	if err != nil {
		return err
	}

	m.SignKey = pubBin
	m.Signature = sig

	return nil
}
