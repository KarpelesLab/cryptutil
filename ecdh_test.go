package cryptutil_test

import (
	"bytes"
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
