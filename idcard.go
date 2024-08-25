package cryptutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// IDCard is a basic ID for a given signature key that allows it to
// specify keys that can be used for encryption/etc
type IDCard struct {
	Self    []byte            `json:"self" cbor:"1,keyasint"` // our own public key (PKIX)
	Issued  time.Time         `json:"iss" cbor:"2,keyasint"`  // issuance date. If two IDCard exist for the same public key, the most recent one will be taken into account
	SubKeys []*SubKey         `json:"sub" cbor:"3,keyasint"`  // known sub keys
	Revoke  []*SubKey         `json:"rev" cbor:"4,keyasint"`  // any key into the revoke list will be strongly rejected
	Groups  []*Membership     `json:"grp" cbor:"5,keyasint"`  // groups this key is member of
	Meta    map[string]string `json:"meta" cbor:"6,keyasint"` // self-defined metadata
}

// SubKey is a key found in a given id card
type SubKey struct {
	Key      []byte     `json:"key" cbor:"1,keyasint"`                     // public key as PKIX
	Issued   time.Time  `json:"iss" cbor:"2,keyasint"`                     // issuance (addition) date
	Expires  *time.Time `json:"exp,omitempty" cbor:"3,keyasint,omitempty"` // expiration date (if any)
	Purposes []string   `json:"pur" cbor:"4,keyasint"`                     // purposes: can contain "sign", "decrypt"
}

// NewIDCard generates a new ID card for the given public key
func NewIDCard(k crypto.PublicKey) (*IDCard, error) {
	pub, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	res := &IDCard{
		Self:   pub,
		Issued: now,
		SubKeys: []*SubKey{
			&SubKey{
				Key:      pub,
				Issued:   now,
				Purposes: []string{"sign"},
			},
		},
	}

	return res, nil
}

// GetKeys returns all the keys of an IDCard that fit a given purpose
func (id *IDCard) GetKeys(purpose string) []crypto.PublicKey {
	var res []crypto.PublicKey
	for _, sub := range id.SubKeys {
		good := false
		for _, p := range sub.Purposes {
			if p == purpose {
				good = true
				break
			}
		}
		if !good {
			continue
		}
		if sub.Expires != nil {
			if time.Until(*sub.Expires) <= 0 {
				continue
			}
		}
		dec, err := x509.ParsePKIXPublicKey(sub.Key)
		if err == nil {
			res = append(res, dec)
		}
	}
	return res
}

// TestKeyPurpose return nil if the provided key is fit for the given purpose, a not found error if the key
// couldn't be found, or a ErrKeyUnfit
func (id *IDCard) TestKeyPurpose(k crypto.PublicKey, purpose string) error {
	sk, err := id.FindKey(k, false)
	if err != nil {
		return err
	}
	if !sk.HasPurpose(purpose) {
		return fmt.Errorf("%w for purpose %s", ErrKeyUnfit, purpose)
	}
	return nil
}

// FindKey locates the [SubKey] matching the given key, and optionally creates one if create is set to true
func (id *IDCard) FindKey(k crypto.PublicKey, create bool) (*SubKey, error) {
	bin, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}

	for _, sub := range id.SubKeys {
		// we don't really care about being subtle here
		if bytes.Equal(sub.Key, bin) {
			return sub, nil
		}
	}

	if !create {
		return nil, ErrKeyNotFound
	}
	sub := &SubKey{
		Key:    bin,
		Issued: time.Now(),
	}
	id.SubKeys = append(id.SubKeys, sub)
	return sub, nil
}

// FindGroup locates the [Membership] matching the given key
func (id *IDCard) FindGroup(k any) (*Membership, error) {
	switch k := k.(type) {
	case []byte:
		for _, g := range id.Groups {
			if bytes.Equal(g.Key, k) {
				return g, nil
			}
		}
		return nil, ErrGroupNotFound
	default:
		bin, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		return id.FindGroup(bin)
	}
}

// SetKeyPurposes specifies the purpose of a given key (sign, decrypt, etc)
func (id *IDCard) SetKeyPurposes(k crypto.PublicKey, purposes ...string) error {
	sub, err := id.FindKey(k, true)
	if err != nil {
		return err
	}
	sub.Purposes = purposes
	return nil
}

// SetKeyDuration specifies the duration for the given key
func (id *IDCard) SetKeyDuration(k crypto.PublicKey, t time.Duration) error {
	sub, err := id.FindKey(k, true)
	if err != nil {
		return err
	}
	exp := time.Now().Add(t)
	sub.Expires = &exp
	return nil
}

// UnmarshalBinary will read a signed ID card, returning an error if it wasn't signed
func (id *IDCard) UnmarshalBinary(b []byte) error {
	res, info, err := (&Opener{}).OpenCbor(b)
	if err != nil {
		return err
	}
	err = cbor.Unmarshal(res, id)
	if err != nil {
		return err
	}
	isSigned := false
	for _, sig := range info.Signatures {
		if bytes.Equal(sig.Signer, id.Self) {
			isSigned = true
			break
		}
	}
	if !isSigned {
		return errors.New("ID Card is not signed by the owner")
	}

	return nil
}

// Sign will return a signed bottle containing this ID Card
func (id *IDCard) Sign(rand io.Reader, k crypto.Signer) ([]byte, error) {
	buf, err := cbor.Marshal(id)
	if err != nil {
		return nil, err
	}
	bottle := NewBottle(buf)
	bottle.Header["ct"] = "idcard"
	err = bottle.BottleUp()
	if err != nil {
		return nil, err
	}
	err = bottle.Sign(rand, k)
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(bottle)
}

// AddKeychain adds the keys found in [Keychain] to the IDCard.
func (id *IDCard) AddKeychain(kc *Keychain) {
	now := time.Now()
	known := make(map[string]bool)
	for _, k := range id.SubKeys {
		known[string(k.Key)] = true
	}
	for pub, priv := range kc.keys {
		if _, found := known[pub]; found {
			continue
		}
		sk := &SubKey{
			Key:      []byte(pub),
			Issued:   now,
			Purposes: guessPurposes(priv.Public()),
		}
		id.SubKeys = append(id.SubKeys, sk)
	}
}

// HasPurpose returns true if the key has the specified purpose listed
func (sk *SubKey) HasPurpose(purpose string) bool {
	for _, p := range sk.Purposes {
		if purpose == p {
			return true
		}
	}
	return false
}
