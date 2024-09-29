package cryptutil

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
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
func (id *IDCard) TestKeyPurpose(k any, purpose string) error {
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
func (id *IDCard) FindKey(k any, create bool) (*SubKey, error) {
	switch v := k.(type) {
	case interface{ Equal(x crypto.PublicKey) bool }:
		// this is a pubkey
		bin, err := x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return nil, err
		}
		return id.FindKey(bin, create)
	case []byte:
		for _, sub := range id.SubKeys {
			// we don't really care about being subtle here
			if bytes.Equal(sub.Key, v) {
				return sub, nil
			}
		}

		if !create {
			return nil, ErrKeyNotFound
		}
		sub := &SubKey{
			Key:    v,
			Issued: time.Now(),
		}
		id.SubKeys = append(id.SubKeys, sub)
		return sub, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", k)
	}
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
	sort.Strings(purposes)
	sub.Purposes = purposes
	return nil
}

// AddKeyPurpose adds the given purpose(s) to the given key
func (id *IDCard) AddKeyPurpose(k crypto.PublicKey, purposes ...string) error {
	sub, err := id.FindKey(k, true)
	if err != nil {
		return err
	}
	sub.AddPurpose(purposes...)
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
	res, info, err := EmptyOpener.OpenCbor(b)
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
	known := make(map[string]*SubKey)
	for _, k := range id.SubKeys {
		known[string(k.Key)] = k
	}
	for pubStr, priv := range kc.keys {
		pubBin := []byte(pubStr)
		pub, err := x509.ParsePKIXPublicKey(pubBin)
		if err != nil {
			continue
		}

		if obj, ok := priv.(interface{ KeyPurposes() []string }); ok {
			pur := obj.KeyPurposes()
			if len(pur) == 0 {
				continue
			}
			if sk, found := known[pubStr]; found {
				sk.AddPurpose(pur...)
				continue
			}

			sort.Strings(pur)

			sk := &SubKey{
				Key:      pubBin,
				Issued:   now,
				Purposes: pur,
			}
			known[pubStr] = sk
			id.SubKeys = append(id.SubKeys, sk)
			continue
		}

		var pur []string

		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			pur = []string{"sign"}

			// check the private key to see if it also supports encryption
			switch sub := priv.(type) {
			case ECDHHandler:
				// the key can be used for encryption directly
				pur = append(pur, "decrypt")
			case interface {
				ECDH() (*ecdh.PrivateKey, error)
			}:
				// the private key can be represented as a ECDH key, let's fetch it
				privKey, err := sub.ECDH()
				if err == nil {
					subPub, err := x509.MarshalPKIXPublicKey(PublicKey(privKey))
					if err == nil {
						// is that the exact same key? It shouldn't but let's check just in case
						if bytes.Equal(subPub, pubBin) {
							// yes
							pur = append(pur, "decrypt")
						} else if sk, found := known[string(subPub)]; !found {
							// append it now
							sk = &SubKey{
								Key:      subPub,
								Issued:   now,
								Purposes: []string{"decrypt"},
							}
							known[string(subPub)] = sk
							id.SubKeys = append(id.SubKeys, sk)
						} else {
							sk.AddPurpose("decrypt")
						}
					}
				}
			case crypto.Decrypter:
				// standard RSA/etc key
				pur = append(pur, "decrypt")
			}
		case *ecdh.PublicKey:
			pur = []string{"decrypt"}
		}
		if len(pur) == 0 {
			// unsupported public key?
			continue
		}

		if sk, found := known[pubStr]; found {
			sk.AddPurpose(pur...)
			continue
		}

		sk := &SubKey{
			Key:      pubBin,
			Issued:   now,
			Purposes: pur,
		}
		known[pubStr] = sk
		id.SubKeys = append(id.SubKeys, sk)
	}
}

// UpdateGroups update the attached memberships based on the provided data
func (id *IDCard) UpdateGroups(data [][]byte) error {
	var err error

main:
	for _, buf := range data {
		var m *Membership
		err = cbor.Unmarshal(buf, &m)
		if err != nil {
			return fmt.Errorf("failed to unmarshal membership: %w", err)
		}
		// check if it's an update for us
		if !bytes.Equal(m.Subject, id.Self) {
			continue
		}
		// check signature
		err = m.Verify(nil)
		if err != nil {
			return fmt.Errorf("failed to verify membership: %w", err)
		}
		if m.Status != "valid" {
			// check if we have this membership, if so remove it
			id.Groups = slices.DeleteFunc(id.Groups, func(sub *Membership) bool {
				return bytes.Equal(sub.Key, m.Key)
			})
			continue
		}
		// remove subject
		m.Subject = nil
		// update membership if we have it
		for n, sub := range id.Groups {
			if bytes.Equal(sub.Key, m.Key) {
				id.Groups[n] = m
				continue main
			}
		}
		// append
		id.Groups = append(id.Groups, m)
	}
	return nil
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

func (sk *SubKey) AddPurpose(purpose ...string) {
	for _, p := range purpose {
		if !sk.HasPurpose(p) {
			sk.Purposes = append(sk.Purposes, p)
		}
	}
	sort.Strings(sk.Purposes)
}

func (sk *SubKey) String() string {
	k := base64.RawURLEncoding.EncodeToString(sk.Key)
	if sk.Expires == nil {
		return fmt.Sprintf("SubKey[%s purposes:%v issued:%s]", k, sk.Purposes, sk.Issued)
	}
	return fmt.Sprintf("SubKey[%s purposes:%v issued:%s expires:%s]", k, sk.Purposes, sk.Issued, *sk.Expires)
}
