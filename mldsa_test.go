package cryptutil_test

import (
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/mldsa"
)

func TestMLDSA44SignVerify(t *testing.T) {
	key, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-44 key: %v", err)
	}

	message := []byte("test message for ML-DSA-44")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.PublicKey(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}

	// Test with wrong message
	err = cryptutil.Verify(key.PublicKey(), []byte("wrong message"), sig)
	if err == nil {
		t.Error("verification should fail with wrong message")
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}

	message := []byte("test message for ML-DSA-65")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.PublicKey(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
}

func TestMLDSA87SignVerify(t *testing.T) {
	key, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-87 key: %v", err)
	}

	message := []byte("test message for ML-DSA-87")

	sig, err := cryptutil.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	err = cryptutil.Verify(key.PublicKey(), message, sig)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
}

func TestMLDSA65WithContext(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}

	message := []byte("test message with context")
	opts := &mldsa.SignerOpts{Context: []byte("test context")}

	sig, err := cryptutil.Sign(rand.Reader, key, message, opts)
	if err != nil {
		t.Fatalf("failed to sign with context: %v", err)
	}

	err = cryptutil.Verify(key.PublicKey(), message, sig, opts)
	if err != nil {
		t.Errorf("failed to verify with context: %v", err)
	}

	// Verify should fail with wrong context
	wrongOpts := &mldsa.SignerOpts{Context: []byte("wrong context")}
	err = cryptutil.Verify(key.PublicKey(), message, sig, wrongOpts)
	if err == nil {
		t.Error("verification should fail with wrong context")
	}
}

func TestMLDSA65PKIXMarshalUnmarshal(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}

	// Marshal public key
	pubDER, err := cryptutil.MarshalPKIXPublicKey(key.PublicKey())
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

func TestMLDSA44PKIXMarshalUnmarshal(t *testing.T) {
	key, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-44 key: %v", err)
	}

	pubDER, err := cryptutil.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	parsedPub, err := cryptutil.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

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

func TestMLDSA87PKIXMarshalUnmarshal(t *testing.T) {
	key, err := mldsa.GenerateKey87(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-87 key: %v", err)
	}

	pubDER, err := cryptutil.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	parsedPub, err := cryptutil.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

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

func TestMLDSAPrivateKeyMarshalUnmarshal(t *testing.T) {
	key, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}

	// Marshal private key
	privDER, err := cryptutil.MarshalMLDSAPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	// Parse private key
	parsedKey, err := cryptutil.ParseMLDSAPrivateKey(privDER)
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
	err = cryptutil.Verify(key.PublicKey(), message, sig)
	if err != nil {
		t.Errorf("failed to verify signature from parsed key: %v", err)
	}
}

func TestBottleWithMLDSA(t *testing.T) {
	// Generate ML-DSA key for signing
	mldsaKey, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA key: %v", err)
	}

	// Create and sign a bottle
	bottle := cryptutil.NewBottle([]byte("Post-quantum signed message"))
	err = bottle.Sign(rand.Reader, mldsaKey)
	if err != nil {
		t.Fatalf("failed to sign bottle: %v", err)
	}

	// Open and verify
	opener := cryptutil.MustOpener()
	msg, info, err := opener.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	if string(msg) != "Post-quantum signed message" {
		t.Errorf("unexpected message: %s", msg)
	}

	if !info.SignedBy(mldsaKey.PublicKey()) {
		t.Error("bottle should be signed by ML-DSA key")
	}
}

func TestBottleWithMLDSAAndEncryption(t *testing.T) {
	// Generate ML-DSA key for signing
	mldsaKey, err := mldsa.GenerateKey65(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA key: %v", err)
	}

	// Create bottle, encrypt for Bob, sign with ML-DSA
	bottle := cryptutil.NewBottle([]byte("Encrypted and PQ-signed"))
	err = bottle.Encrypt(rand.Reader, bob.Public())
	if err != nil {
		t.Fatalf("failed to encrypt bottle: %v", err)
	}
	err = bottle.BottleUp()
	if err != nil {
		t.Fatalf("failed to bottle up: %v", err)
	}
	err = bottle.Sign(rand.Reader, mldsaKey)
	if err != nil {
		t.Fatalf("failed to sign bottle: %v", err)
	}

	// Open with Bob's key
	opener := cryptutil.MustOpener(bob)
	msg, info, err := opener.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	if string(msg) != "Encrypted and PQ-signed" {
		t.Errorf("unexpected message: %s", msg)
	}

	if !info.SignedBy(mldsaKey.PublicKey()) {
		t.Error("bottle should be signed by ML-DSA key")
	}

	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}
}
