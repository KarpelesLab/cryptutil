package cryptutil_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Errorf("must assertion failed: %w", err))
	}
	return v
}

var (
	alice = must(ecdh.P256().NewPrivateKey(must(base64.RawURLEncoding.DecodeString("_J1nPevoYc3bYCs7htscdnPgregNasbZcufMTKkF3LI"))))
	bob   = must(ecdh.P256().NewPrivateKey(must(base64.RawURLEncoding.DecodeString("w9V4eOe1TdFpNaA-omztVs090w6hd8rPBT47e_gfF-Y"))))
)

func TestCryptECDH(t *testing.T) {
	msg := []byte("message to alice")
	enc, err := cryptutil.ECDHEncrypt(msg, alice.PublicKey(), nil)
	if err != nil {
		t.Errorf("failed to encrypt: %s", err)
	}

	dec, err := cryptutil.ECDHDecrypt(enc, alice)
	if err != nil {
		t.Errorf("failed to decrypt: %s", err)
	}

	if !bytes.Equal(dec, msg) {
		t.Errorf("decrypted message does not match original message")
	}
}
