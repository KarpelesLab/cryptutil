package cryptutil_test

import (
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/slhdsa"
)

func TestSLHDSA_SHA2_128s_SignVerify(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	message := []byte("test message for SLH-DSA-SHA2-128s")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.Public(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}

	// Test with wrong message
	err = cryptutil.Verify(key.Public(), []byte("wrong message"), sig)
	if err == nil {
		t.Error("verification should fail with wrong message")
	}
}

func TestSLHDSA_SHA2_128f_SignVerify(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	message := []byte("test message for SLH-DSA-SHA2-128f")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.Public(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
}

func TestSLHDSA_SHAKE_128s_SignVerify(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	message := []byte("test message for SLH-DSA-SHAKE-128s")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.Public(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
}

func TestSLHDSA_WithContext(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	message := []byte("test message with context")
	opts := &slhdsa.Options{Context: []byte("test context")}

	sig, err := cryptutil.Sign(rand.Reader, key, message, opts)
	if err != nil {
		t.Fatalf("failed to sign with context: %v", err)
	}

	err = cryptutil.Verify(key.Public(), message, sig, opts)
	if err != nil {
		t.Errorf("failed to verify with context: %v", err)
	}

	// Verify should fail with wrong context
	wrongOpts := &slhdsa.Options{Context: []byte("wrong context")}
	err = cryptutil.Verify(key.Public(), message, sig, wrongOpts)
	if err == nil {
		t.Error("verification should fail with wrong context")
	}
}

func TestSLHDSA_PKIXMarshalUnmarshal(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	// Marshal public key
	pubDER, err := cryptutil.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	// Parse public key
	parsedPub, err := cryptutil.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	// Verify with parsed key
	message := []byte("test message")
	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(parsedPub, message, sig)
	if err != nil {
		t.Errorf("failed to verify with parsed key: %v", err)
	}
}

func TestSLHDSA_PrivateKeyMarshalUnmarshal(t *testing.T) {
	key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	// Marshal private key
	privDER, err := cryptutil.MarshalSLHDSAPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	// Parse private key
	parsedKey, err := cryptutil.ParseSLHDSAPrivateKey(privDER)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Sign with parsed key
	message := []byte("test message")
	sig, err := cryptutil.Sign(rand.Reader, parsedKey, message)
	if err != nil {
		t.Fatalf("failed to sign with parsed key: %v", err)
	}

	// Verify with original public key
	err = cryptutil.Verify(key.Public(), message, sig)
	if err != nil {
		t.Errorf("failed to verify signature from parsed key: %v", err)
	}
}

func TestSLHDSA_AllParamsPKIX(t *testing.T) {
	params := []*slhdsa.Params{
		slhdsa.SHA2_128s, slhdsa.SHA2_128f,
		slhdsa.SHA2_192s, slhdsa.SHA2_192f,
		slhdsa.SHA2_256s, slhdsa.SHA2_256f,
		slhdsa.SHAKE_128s, slhdsa.SHAKE_128f,
		slhdsa.SHAKE_192s, slhdsa.SHAKE_192f,
		slhdsa.SHAKE_256s, slhdsa.SHAKE_256f,
	}

	for _, p := range params {
		t.Run(p.String(), func(t *testing.T) {
			key, err := slhdsa.GenerateKey(rand.Reader, p)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			pubDER, err := cryptutil.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatalf("failed to marshal public key: %v", err)
			}

			parsedPub, err := cryptutil.ParsePKIXPublicKey(pubDER)
			if err != nil {
				t.Fatalf("failed to parse public key: %v", err)
			}

			message := []byte("test")
			sig, err := cryptutil.Sign(rand.Reader, key, message)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			err = cryptutil.Verify(parsedPub, message, sig)
			if err != nil {
				t.Errorf("failed to verify: %v", err)
			}
		})
	}
}

func TestBottleWithSLHDSA(t *testing.T) {
	// Generate SLH-DSA key for signing
	slhdsaKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	// Create and sign a bottle
	bottle := cryptutil.NewBottle([]byte("Hash-based signed message"))
	err = bottle.Sign(rand.Reader, slhdsaKey)
	if err != nil {
		t.Fatalf("failed to sign bottle: %v", err)
	}

	// Open and verify
	opener := cryptutil.MustOpener()
	msg, info, err := opener.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	if string(msg) != "Hash-based signed message" {
		t.Errorf("unexpected message: %s", msg)
	}

	if !info.SignedBy(slhdsaKey.Public()) {
		t.Error("bottle should be signed by SLH-DSA key")
	}
}

func TestBottleWithSLHDSAAndEncryption(t *testing.T) {
	// Generate SLH-DSA key for signing
	slhdsaKey, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("failed to generate SLH-DSA key: %v", err)
	}

	// Create bottle, encrypt for Bob, sign with SLH-DSA
	bottle := cryptutil.NewBottle([]byte("Encrypted and hash-based signed"))
	err = bottle.Encrypt(rand.Reader, bob.Public())
	if err != nil {
		t.Fatalf("failed to encrypt bottle: %v", err)
	}
	err = bottle.BottleUp()
	if err != nil {
		t.Fatalf("failed to bottle up: %v", err)
	}
	err = bottle.Sign(rand.Reader, slhdsaKey)
	if err != nil {
		t.Fatalf("failed to sign bottle: %v", err)
	}

	// Open with Bob's key
	opener := cryptutil.MustOpener(bob)
	msg, info, err := opener.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	if string(msg) != "Encrypted and hash-based signed" {
		t.Errorf("unexpected message: %s", msg)
	}

	if !info.SignedBy(slhdsaKey.Public()) {
		t.Error("bottle should be signed by SLH-DSA key")
	}

	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}
}
