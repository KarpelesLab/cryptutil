// Package cryptutil provides cryptographic utilities for secure message handling.
//
// Deprecated: This package has been renamed and moved to a new location.
// Please update your imports to use github.com/BottleFmt/gobottle instead.
//
// To migrate:
//
//	go get github.com/BottleFmt/gobottle@latest
//
// Then update your imports from:
//
//	import "github.com/KarpelesLab/cryptutil"
//
// To:
//
//	import "github.com/BottleFmt/gobottle"
package cryptutil

import (
	"crypto"
	"crypto/ecdh"
	"hash"
	"io"
	"net/http"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/slhdsa"
)

// Type aliases - all types are re-exported from gobottle

// Deprecated: Use gobottle.MessageFormat instead.
type MessageFormat = gobottle.MessageFormat

// Deprecated: Use gobottle.Bottle instead.
type Bottle = gobottle.Bottle

// Deprecated: Use gobottle.MessageRecipient instead.
type MessageRecipient = gobottle.MessageRecipient

// Deprecated: Use gobottle.MessageSignature instead.
type MessageSignature = gobottle.MessageSignature

// Deprecated: Use gobottle.ECDHHandler instead.
type ECDHHandler = gobottle.ECDHHandler

// Deprecated: Use gobottle.IDCard instead.
type IDCard = gobottle.IDCard

// Deprecated: Use gobottle.SubKey instead.
type SubKey = gobottle.SubKey

// Deprecated: Use gobottle.Keychain instead.
type Keychain = gobottle.Keychain

// Deprecated: Use gobottle.Membership instead.
type Membership = gobottle.Membership

// Deprecated: Use gobottle.MLKEMVariant instead.
type MLKEMVariant = gobottle.MLKEMVariant

// Deprecated: Use gobottle.MLKEMPublicKey instead.
type MLKEMPublicKey = gobottle.MLKEMPublicKey

// Deprecated: Use gobottle.MLKEMPrivateKey instead.
type MLKEMPrivateKey = gobottle.MLKEMPrivateKey

// Deprecated: Use gobottle.Opener instead.
type Opener = gobottle.Opener

// Deprecated: Use gobottle.OpenResult instead.
type OpenResult = gobottle.OpenResult

// Deprecated: Use gobottle.PrivateKey instead.
type PrivateKey = gobottle.PrivateKey

// Deprecated: Use gobottle.PublicKeyIntf instead.
type PublicKeyIntf = gobottle.PublicKeyIntf

// Deprecated: Use gobottle.MLDSAVariant instead.
type MLDSAVariant = gobottle.MLDSAVariant

// Constants - re-exported from gobottle

// Deprecated: Use gobottle.ClearText instead.
const ClearText = gobottle.ClearText

// Deprecated: Use gobottle.CborBottle instead.
const CborBottle = gobottle.CborBottle

// Deprecated: Use gobottle.AES instead.
const AES = gobottle.AES

// Deprecated: Use gobottle.JsonBottle instead.
const JsonBottle = gobottle.JsonBottle

// Deprecated: Use gobottle.MLKEM768 instead.
const MLKEM768 = gobottle.MLKEM768

// Deprecated: Use gobottle.MLKEM1024 instead.
const MLKEM1024 = gobottle.MLKEM1024

// Deprecated: Use gobottle.MLDSA44 instead.
const MLDSA44 = gobottle.MLDSA44

// Deprecated: Use gobottle.MLDSA65 instead.
const MLDSA65 = gobottle.MLDSA65

// Deprecated: Use gobottle.MLDSA87 instead.
const MLDSA87 = gobottle.MLDSA87

// Variables - re-exported from gobottle

// Deprecated: Use gobottle.ErrNoAppropriateKey instead.
var ErrNoAppropriateKey = gobottle.ErrNoAppropriateKey

// Deprecated: Use gobottle.ErrVerifyFailed instead.
var ErrVerifyFailed = gobottle.ErrVerifyFailed

// Deprecated: Use gobottle.ErrKeyNotFound instead.
var ErrKeyNotFound = gobottle.ErrKeyNotFound

// Deprecated: Use gobottle.ErrGroupNotFound instead.
var ErrGroupNotFound = gobottle.ErrGroupNotFound

// Deprecated: Use gobottle.ErrKeyUnfit instead.
var ErrKeyUnfit = gobottle.ErrKeyUnfit

// Deprecated: Use gobottle.ErrEncryptNoRecipient instead.
var ErrEncryptNoRecipient = gobottle.ErrEncryptNoRecipient

// Deprecated: Use gobottle.EmptyOpener instead.
var EmptyOpener = gobottle.EmptyOpener

// Functions - wrappers around gobottle functions

// Deprecated: Use gobottle.MemClr instead.
func MemClr(b []byte) {
	gobottle.MemClr(b)
}

// Deprecated: Use gobottle.Hash instead.
func Hash(b []byte, alg ...func() hash.Hash) []byte {
	return gobottle.Hash(b, alg...)
}

// Deprecated: Use gobottle.PublicKey instead.
func PublicKey(privKey crypto.PrivateKey) PublicKeyIntf {
	return gobottle.PublicKey(privKey)
}

// Deprecated: Use gobottle.EncryptShortBuffer instead.
func EncryptShortBuffer(rand io.Reader, k []byte, rcvd crypto.PublicKey) ([]byte, error) {
	return gobottle.EncryptShortBuffer(rand, k, rcvd)
}

// Deprecated: Use gobottle.DecryptShortBuffer instead.
func DecryptShortBuffer(k []byte, rcvd any) ([]byte, error) {
	return gobottle.DecryptShortBuffer(k, rcvd)
}

// Deprecated: Use gobottle.NewBottle instead.
func NewBottle(data []byte) *Bottle {
	return gobottle.NewBottle(data)
}

// Deprecated: Use gobottle.Marshal instead.
func Marshal(data any) (*Bottle, error) {
	return gobottle.Marshal(data)
}

// Deprecated: Use gobottle.MarshalJson instead.
func MarshalJson(data any) (*Bottle, error) {
	return gobottle.MarshalJson(data)
}

// Deprecated: Use gobottle.AsCborBottle instead.
func AsCborBottle(data []byte) *Bottle {
	return gobottle.AsCborBottle(data)
}

// Deprecated: Use gobottle.AsJsonBottle instead.
func AsJsonBottle(data []byte) *Bottle {
	return gobottle.AsJsonBottle(data)
}

// Deprecated: Use gobottle.ECDHEncrypt instead.
func ECDHEncrypt(rnd io.Reader, data []byte, remote *ecdh.PublicKey) ([]byte, error) {
	return gobottle.ECDHEncrypt(rnd, data, remote)
}

// Deprecated: Use gobottle.ECDHDecrypt instead.
func ECDHDecrypt(data []byte, privateKey ECDHHandler) ([]byte, error) {
	return gobottle.ECDHDecrypt(data, privateKey)
}

// Deprecated: Use gobottle.NewIDCard instead.
func NewIDCard(k crypto.PublicKey) (*IDCard, error) {
	return gobottle.NewIDCard(k)
}

// Deprecated: Use gobottle.NewKeychain instead.
func NewKeychain() *Keychain {
	return gobottle.NewKeychain()
}

// Deprecated: Use gobottle.NewMembership instead.
func NewMembership(member *IDCard, key []byte) *Membership {
	return gobottle.NewMembership(member, key)
}

// Deprecated: Use gobottle.GenerateMLKEMKey instead.
func GenerateMLKEMKey(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	return gobottle.GenerateMLKEMKey(rand, hybrid)
}

// Deprecated: Use gobottle.GenerateMLKEMKey768 instead.
func GenerateMLKEMKey768(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	return gobottle.GenerateMLKEMKey768(rand, hybrid)
}

// Deprecated: Use gobottle.GenerateMLKEMKey1024 instead.
func GenerateMLKEMKey1024(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	return gobottle.GenerateMLKEMKey1024(rand, hybrid)
}

// Deprecated: Use gobottle.ParseMLKEMPublicKey instead.
func ParseMLKEMPublicKey(der []byte) (*MLKEMPublicKey, error) {
	return gobottle.ParseMLKEMPublicKey(der)
}

// Deprecated: Use gobottle.ParseMLKEMPrivateKey instead.
func ParseMLKEMPrivateKey(der []byte) (*MLKEMPrivateKey, error) {
	return gobottle.ParseMLKEMPrivateKey(der)
}

// Deprecated: Use gobottle.HybridEncrypt instead.
func HybridEncrypt(rnd io.Reader, data []byte, remote *MLKEMPublicKey) ([]byte, error) {
	return gobottle.HybridEncrypt(rnd, data, remote)
}

// Deprecated: Use gobottle.MLKEMEncrypt instead.
func MLKEMEncrypt(rnd io.Reader, data []byte, remote *MLKEMPublicKey) ([]byte, error) {
	return gobottle.MLKEMEncrypt(rnd, data, remote)
}

// Deprecated: Use gobottle.MLKEMDecrypt instead.
func MLKEMDecrypt(data []byte, privateKey *MLKEMPrivateKey) ([]byte, error) {
	return gobottle.MLKEMDecrypt(data, privateKey)
}

// Deprecated: Use gobottle.MarshalMLKEMPublicKey instead.
func MarshalMLKEMPublicKey(k *MLKEMPublicKey) []byte {
	return gobottle.MarshalMLKEMPublicKey(k)
}

// Deprecated: Use gobottle.UnmarshalMLKEMPublicKey instead.
func UnmarshalMLKEMPublicKey(data []byte) (*MLKEMPublicKey, error) {
	return gobottle.UnmarshalMLKEMPublicKey(data)
}

// Deprecated: Use gobottle.MarshalMLKEMPrivateKey instead.
func MarshalMLKEMPrivateKey(k *MLKEMPrivateKey) []byte {
	return gobottle.MarshalMLKEMPrivateKey(k)
}

// Deprecated: Use gobottle.UnmarshalMLKEMPrivateKey instead.
func UnmarshalMLKEMPrivateKey(data []byte) (*MLKEMPrivateKey, error) {
	return gobottle.UnmarshalMLKEMPrivateKey(data)
}

// Deprecated: Use gobottle.NewOpener instead.
func NewOpener(keys ...any) (*Opener, error) {
	return gobottle.NewOpener(keys...)
}

// Deprecated: Use gobottle.MustOpener instead.
func MustOpener(keys ...any) *Opener {
	return gobottle.MustOpener(keys...)
}

// Deprecated: Use gobottle.MarshalMLDSAPublicKey instead.
func MarshalMLDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return gobottle.MarshalMLDSAPublicKey(pub)
}

// Deprecated: Use gobottle.ParseMLDSAPublicKey instead.
func ParseMLDSAPublicKey(der []byte) (crypto.PublicKey, error) {
	return gobottle.ParseMLDSAPublicKey(der)
}

// Deprecated: Use gobottle.MarshalMLDSAPrivateKey instead.
func MarshalMLDSAPrivateKey(key crypto.Signer) ([]byte, error) {
	return gobottle.MarshalMLDSAPrivateKey(key)
}

// Deprecated: Use gobottle.ParseMLDSAPrivateKey instead.
func ParseMLDSAPrivateKey(der []byte) (crypto.Signer, error) {
	return gobottle.ParseMLDSAPrivateKey(der)
}

// Deprecated: Use gobottle.MarshalSLHDSAPublicKey instead.
func MarshalSLHDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return gobottle.MarshalSLHDSAPublicKey(pub)
}

// Deprecated: Use gobottle.ParseSLHDSAPublicKey instead.
func ParseSLHDSAPublicKey(der []byte) (*slhdsa.PublicKey, error) {
	return gobottle.ParseSLHDSAPublicKey(der)
}

// Deprecated: Use gobottle.MarshalSLHDSAPrivateKey instead.
func MarshalSLHDSAPrivateKey(key *slhdsa.PrivateKey) ([]byte, error) {
	return gobottle.MarshalSLHDSAPrivateKey(key)
}

// Deprecated: Use gobottle.ParseSLHDSAPrivateKey instead.
func ParseSLHDSAPrivateKey(der []byte) (*slhdsa.PrivateKey, error) {
	return gobottle.ParseSLHDSAPrivateKey(der)
}

// Deprecated: Use gobottle.Sign instead.
func Sign(rand io.Reader, key crypto.Signer, buf []byte, opts ...crypto.SignerOpts) ([]byte, error) {
	return gobottle.Sign(rand, key, buf, opts...)
}

// Deprecated: Use gobottle.Verify instead.
func Verify(key crypto.PublicKey, buf, sig []byte, opts ...crypto.SignerOpts) error {
	return gobottle.Verify(key, buf, sig, opts...)
}

// Deprecated: Use gobottle.ParsePKIXPublicKey instead.
func ParsePKIXPublicKey(der []byte) (PublicKeyIntf, error) {
	return gobottle.ParsePKIXPublicKey(der)
}

// Deprecated: Use gobottle.MarshalPKIXPublicKey instead.
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return gobottle.MarshalPKIXPublicKey(pub)
}

// Deprecated: Use gobottle.UnmarshalHttp instead.
func UnmarshalHttp(req *http.Request, v any, keys ...any) (*OpenResult, error) {
	o, err := gobottle.NewOpener(keys...)
	if err != nil {
		return nil, err
	}
	return o.UnmarshalHttp(req, v)
}
