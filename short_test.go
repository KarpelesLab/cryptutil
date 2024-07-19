package cryptutil_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

func TestShortEdwards(t *testing.T) {
	// test ecdh over ed25519 using ShortBuffer methods (simplified)
	// ed25519 cannot be used directly in x25519 encryption and requires some tweaks to work right
	msg := []byte("message to daniel")
	enc, err := cryptutil.EncryptShortBuffer(rand.Reader, msg, daniel.(ed25519.PrivateKey).Public())
	if err != nil {
		t.Errorf("failed to encrypt: %s", err)
	}

	dec, err := cryptutil.DecryptShortBuffer(enc, daniel)
	if err != nil {
		t.Errorf("failed to decrypt: %s", err)
	}

	if !bytes.Equal(dec, msg) {
		t.Errorf("decrypted short message does not match original message")
	}
}
