package cryptutil_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

func TestMLKEMHybridEncryptDecrypt(t *testing.T) {
	// Generate a hybrid ML-KEM key pair
	priv, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	if !priv.IsHybrid() {
		t.Fatal("expected hybrid key")
	}

	pub := priv.MLKEMPublic()
	if !pub.IsHybrid() {
		t.Fatal("expected hybrid public key")
	}

	// Test encryption/decryption
	plaintext := []byte("hello post-quantum world!")
	ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, pub)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, priv)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestMLKEMPureEncryptDecrypt(t *testing.T) {
	// Generate a non-hybrid ML-KEM key pair
	priv, err := cryptutil.GenerateMLKEMKey(rand.Reader, false)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	if priv.IsHybrid() {
		t.Fatal("expected non-hybrid key")
	}

	pub := priv.MLKEMPublic()

	// Test encryption/decryption with pure ML-KEM
	plaintext := []byte("hello pure post-quantum world!")
	ciphertext, err := cryptutil.MLKEMEncrypt(rand.Reader, plaintext, pub)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, priv)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestMLKEM1024HybridEncryptDecrypt(t *testing.T) {
	// Generate a hybrid ML-KEM-1024 key pair
	priv, err := cryptutil.GenerateMLKEMKey1024(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-1024 key: %v", err)
	}

	if !priv.IsHybrid() {
		t.Fatal("expected hybrid key")
	}

	if priv.Variant() != cryptutil.MLKEM1024 {
		t.Fatalf("expected MLKEM1024 variant, got %v", priv.Variant())
	}

	pub := priv.MLKEMPublic()
	if !pub.IsHybrid() {
		t.Fatal("expected hybrid public key")
	}

	// Test encryption/decryption
	plaintext := []byte("hello ML-KEM-1024 post-quantum world!")
	ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, pub)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, priv)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestMLKEM1024KeyMarshalUnmarshal(t *testing.T) {
	// Test ML-KEM-1024 hybrid key marshalling
	priv, err := cryptutil.GenerateMLKEMKey1024(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-1024 key: %v", err)
	}

	pub := priv.MLKEMPublic()

	// Marshal and unmarshal public key
	pubBytes := cryptutil.MarshalMLKEMPublicKey(pub)
	pub2, err := cryptutil.UnmarshalMLKEMPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal public key: %v", err)
	}

	if !pub2.IsHybrid() {
		t.Fatal("expected hybrid public key after unmarshal")
	}

	if pub2.Variant() != cryptutil.MLKEM1024 {
		t.Fatalf("expected MLKEM1024 variant after unmarshal, got %v", pub2.Variant())
	}

	// Marshal and unmarshal private key
	privBytes := cryptutil.MarshalMLKEMPrivateKey(priv)
	priv2, err := cryptutil.UnmarshalMLKEMPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal private key: %v", err)
	}

	if !priv2.IsHybrid() {
		t.Fatal("expected hybrid private key after unmarshal")
	}

	if priv2.Variant() != cryptutil.MLKEM1024 {
		t.Fatalf("expected MLKEM1024 variant after unmarshal, got %v", priv2.Variant())
	}

	// Verify encryption with original key can be decrypted with unmarshalled key
	plaintext := []byte("test ML-KEM-1024 key serialization")
	ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, pub)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, priv2)
	if err != nil {
		t.Fatalf("failed to decrypt with unmarshalled key: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original")
	}
}

func TestMLKEMPKIXEncoding(t *testing.T) {
	// Test PKIX encoding for pure ML-KEM-768 key
	priv768, err := cryptutil.GenerateMLKEMKey768(rand.Reader, false)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM-768 key: %v", err)
	}
	pub768 := priv768.MLKEMPublic()

	pkix768, err := pub768.MarshalPKIXPublicKey()
	if err != nil {
		t.Fatalf("failed to marshal ML-KEM-768 public key to PKIX: %v", err)
	}

	pub768Parsed, err := cryptutil.ParseMLKEMPublicKey(pkix768)
	if err != nil {
		t.Fatalf("failed to parse ML-KEM-768 public key from PKIX: %v", err)
	}

	if pub768Parsed.IsHybrid() {
		t.Error("parsed key should not be hybrid")
	}
	if pub768Parsed.Variant() != cryptutil.MLKEM768 {
		t.Errorf("expected MLKEM768 variant, got %v", pub768Parsed.Variant())
	}

	// Test PKIX encoding for hybrid ML-KEM-768 key
	privHybrid, err := cryptutil.GenerateMLKEMKey768(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate hybrid ML-KEM-768 key: %v", err)
	}
	pubHybrid := privHybrid.MLKEMPublic()

	pkixHybrid, err := pubHybrid.MarshalPKIXPublicKey()
	if err != nil {
		t.Fatalf("failed to marshal hybrid ML-KEM-768 public key to PKIX: %v", err)
	}

	pubHybridParsed, err := cryptutil.ParseMLKEMPublicKey(pkixHybrid)
	if err != nil {
		t.Fatalf("failed to parse hybrid ML-KEM-768 public key from PKIX: %v", err)
	}

	if !pubHybridParsed.IsHybrid() {
		t.Error("parsed key should be hybrid")
	}
	if pubHybridParsed.Variant() != cryptutil.MLKEM768 {
		t.Errorf("expected MLKEM768 variant, got %v", pubHybridParsed.Variant())
	}

	// Test PKCS#8 encoding for private keys
	pkcs8Priv, err := privHybrid.MarshalPKCS8PrivateKey()
	if err != nil {
		t.Fatalf("failed to marshal private key to PKCS#8: %v", err)
	}

	privParsed, err := cryptutil.ParseMLKEMPrivateKey(pkcs8Priv)
	if err != nil {
		t.Fatalf("failed to parse private key from PKCS#8: %v", err)
	}

	if !privParsed.IsHybrid() {
		t.Error("parsed private key should be hybrid")
	}

	// Verify encryption with original key can be decrypted with parsed key
	plaintext := []byte("test PKIX encoding roundtrip")
	ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, pubHybrid)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, privParsed)
	if err != nil {
		t.Fatalf("failed to decrypt with parsed key: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original")
	}
}

func TestGenericParsePKIXPublicKey(t *testing.T) {
	// Test that ParsePKIXPublicKey works for both ML-KEM and classical keys

	// Test with ML-KEM hybrid key
	mlkemPriv, err := cryptutil.GenerateMLKEMKey768(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}
	mlkemPub := mlkemPriv.MLKEMPublic()

	mlkemPKIX, err := cryptutil.MarshalPKIXPublicKey(mlkemPub)
	if err != nil {
		t.Fatalf("failed to marshal ML-KEM public key: %v", err)
	}

	parsedMLKEM, err := cryptutil.ParsePKIXPublicKey(mlkemPKIX)
	if err != nil {
		t.Fatalf("failed to parse ML-KEM PKIX key: %v", err)
	}

	if _, ok := parsedMLKEM.(*cryptutil.MLKEMPublicKey); !ok {
		t.Errorf("expected *MLKEMPublicKey, got %T", parsedMLKEM)
	}

	// Test with classical ECDSA key (using alice from bottle_test.go)
	ecdsaPKIX, err := cryptutil.MarshalPKIXPublicKey(alice.Public())
	if err != nil {
		t.Fatalf("failed to marshal ECDSA public key: %v", err)
	}

	parsedECDSA, err := cryptutil.ParsePKIXPublicKey(ecdsaPKIX)
	if err != nil {
		t.Fatalf("failed to parse ECDSA PKIX key: %v", err)
	}

	if !parsedECDSA.Equal(alice.Public()) {
		t.Error("parsed ECDSA key does not equal original")
	}
}

func TestMLKEMKeyMarshalUnmarshal(t *testing.T) {
	// Test hybrid key marshalling
	priv, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	pub := priv.MLKEMPublic()

	// Marshal and unmarshal public key
	pubBytes := cryptutil.MarshalMLKEMPublicKey(pub)
	pub2, err := cryptutil.UnmarshalMLKEMPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal public key: %v", err)
	}

	if !pub2.IsHybrid() {
		t.Fatal("expected hybrid public key after unmarshal")
	}

	// Marshal and unmarshal private key
	privBytes := cryptutil.MarshalMLKEMPrivateKey(priv)
	priv2, err := cryptutil.UnmarshalMLKEMPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal private key: %v", err)
	}

	if !priv2.IsHybrid() {
		t.Fatal("expected hybrid private key after unmarshal")
	}

	// Verify encryption with original key can be decrypted with unmarshalled key
	plaintext := []byte("test key serialization")
	ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, pub)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cryptutil.MLKEMDecrypt(ciphertext, priv2)
	if err != nil {
		t.Fatalf("failed to decrypt with unmarshalled key: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted data does not match original")
	}
}

func TestBottleWithMLKEMHybrid(t *testing.T) {
	// Generate ML-KEM hybrid key pair for recipient
	recipientPriv, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	recipientPub := recipientPriv.MLKEMPublic()

	// Create and encrypt a bottle
	bottle := cryptutil.NewBottle([]byte("post-quantum secure message"))
	err = bottle.Encrypt(rand.Reader, recipientPub)
	if err != nil {
		t.Fatalf("failed to encrypt bottle: %v", err)
	}

	// Sign with a classical key
	bottle.BottleUp()
	bottle.Sign(rand.Reader, alice)

	// Open the bottle
	opener, err := cryptutil.NewOpener(recipientPriv)
	if err != nil {
		t.Fatalf("failed to create opener: %v", err)
	}

	res, info, err := opener.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}

	if string(res) != "post-quantum secure message" {
		t.Errorf("unexpected message: %s", string(res))
	}

	if !info.SignedBy(alice.Public()) {
		t.Error("expected message to be signed by alice")
	}
}

func TestBottleWithMixedRecipients(t *testing.T) {
	// Generate ML-KEM hybrid key pair
	mlkemPriv, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}
	mlkemPub := mlkemPriv.MLKEMPublic()

	// Create a bottle encrypted for both classical (bob) and ML-KEM recipient
	bottle := cryptutil.NewBottle([]byte("message for mixed recipients"))
	err = bottle.Encrypt(rand.Reader, bob.Public(), mlkemPub)
	if err != nil {
		t.Fatalf("failed to encrypt bottle: %v", err)
	}

	// Verify there are two recipients (all with Type 0, keys identified by PKIX encoding)
	if len(bottle.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(bottle.Recipients))
	}

	// Verify all recipients use Type 0 (PKIX-encoded keys)
	for i, r := range bottle.Recipients {
		if r.Type != 0 {
			t.Errorf("recipient %d: expected Type 0, got %d", i, r.Type)
		}
	}

	// Open with classical key (bob)
	openerBob, err := cryptutil.NewOpener(bob)
	if err != nil {
		t.Fatalf("failed to create opener for bob: %v", err)
	}

	res, info, err := openerBob.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle with bob's key: %v", err)
	}

	if string(res) != "message for mixed recipients" {
		t.Errorf("unexpected message with bob: %s", string(res))
	}

	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption with bob, got %d", info.Decryption)
	}

	// Open with ML-KEM key
	openerMLKEM, err := cryptutil.NewOpener(mlkemPriv)
	if err != nil {
		t.Fatalf("failed to create opener for ML-KEM: %v", err)
	}

	res, info, err = openerMLKEM.Open(bottle)
	if err != nil {
		t.Fatalf("failed to open bottle with ML-KEM key: %v", err)
	}

	if string(res) != "message for mixed recipients" {
		t.Errorf("unexpected message with ML-KEM: %s", string(res))
	}

	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption with ML-KEM, got %d", info.Decryption)
	}
}

func TestShortBufferWithMLKEM(t *testing.T) {
	// Test EncryptShortBuffer and DecryptShortBuffer with ML-KEM
	priv, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	pub := priv.MLKEMPublic()

	// Encrypt a short buffer (like an AES key)
	key := make([]byte, 32)
	rand.Read(key)

	encrypted, err := cryptutil.EncryptShortBuffer(rand.Reader, key, pub)
	if err != nil {
		t.Fatalf("failed to encrypt short buffer: %v", err)
	}

	decrypted, err := cryptutil.DecryptShortBuffer(encrypted, priv)
	if err != nil {
		t.Fatalf("failed to decrypt short buffer: %v", err)
	}

	if !bytes.Equal(key, decrypted) {
		t.Fatalf("decrypted key does not match original")
	}
}
