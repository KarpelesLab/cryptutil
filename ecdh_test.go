package cryptutil_test

import (
	"bytes"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

func TestCryptECDH(t *testing.T) {
	msg := []byte("message to alice")
	enc, err := cryptutil.ECDHEncrypt(nil, msg, must(alice.ECDH()).PublicKey())
	if err != nil {
		t.Errorf("failed to encrypt: %s", err)
	}

	dec, err := cryptutil.ECDHDecrypt(enc, must(alice.ECDH()))
	if err != nil {
		t.Errorf("failed to decrypt: %s", err)
	}

	if !bytes.Equal(dec, msg) {
		t.Errorf("decrypted message does not match original message")
	}
}
