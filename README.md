[![GoDoc](https://godoc.org/github.com/KarpelesLab/cryptutil?status.svg)](https://godoc.org/github.com/KarpelesLab/cryptutil)
[![CI](https://github.com/KarpelesLab/cryptutil/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/cryptutil/actions/workflows/ci.yml)

# cryptutil

A comprehensive Go cryptographic utility library providing high-level APIs for encryption, signing, and key management. Supports both classical (ECDSA, Ed25519, RSA) and post-quantum (ML-KEM) cryptography.

## Installation

```bash
go get github.com/KarpelesLab/cryptutil
```

Requires Go 1.24 or later.

## Features

- **Bottle**: Layered message containers with encryption and signatures
- **ML-KEM**: Post-quantum encryption (ML-KEM-768, ML-KEM-1024) with optional X25519 hybrid mode
- **ECDH Encryption**: Simple message encryption to ECDSA/ECDH keys
- **IDCard**: Identity management with sub-keys and key purposes
- **Keychain**: Secure key storage and management
- **Membership**: Cryptographically signed group memberships

## Bottle

Bottles are versatile containers for arbitrary data that support multiple layers of encryption and signatures. They can be serialized as CBOR or JSON.

### Creating and Opening Bottles

```go
import (
    "crypto/rand"
    "github.com/KarpelesLab/cryptutil"
)

// Create a bottle with a message
bottle := cryptutil.NewBottle([]byte("secret message"))

// Encrypt for one or more recipients (any recipient can decrypt)
bottle.Encrypt(rand.Reader, bobPublicKey, alicePublicKey)

// Wrap in another layer to include encryption metadata in signature
bottle.BottleUp()

// Sign the bottle
bottle.Sign(rand.Reader, senderPrivateKey)

// Open the bottle (Bob decrypts)
opener, err := cryptutil.NewOpener(bobPrivateKey)
message, info, err := opener.Open(bottle)

// Check who signed it
if info.SignedBy(senderPublicKey) {
    fmt.Println("Verified signature from sender")
}
fmt.Printf("Decryption layers: %d\n", info.Decryption)
```

### Bottle with Structured Data

```go
// Marshal Go structs directly into bottles
type MyData struct {
    Name  string `json:"name"`
    Value int    `json:"value"`
}

// CBOR encoding (compact, binary)
bottle, err := cryptutil.Marshal(MyData{Name: "test", Value: 42})

// JSON encoding
bottle, err := cryptutil.MarshalJson(MyData{Name: "test", Value: 42})

// Unmarshal from bottle
var data MyData
opener := cryptutil.MustOpener(privateKey)
info, err := opener.Unmarshal(bottle, &data)
```

### Opening Encoded Bottles

```go
// Open CBOR-encoded bottle directly
message, info, err := opener.OpenCbor(cborBytes)

// Open from HTTP request (handles Content-Type)
message, info, err := opener.OpenHttp(httpRequest)
```

## ML-KEM Post-Quantum Encryption

ML-KEM (formerly CRYSTALS-Kyber) provides quantum-resistant key encapsulation. The library supports hybrid mode combining ML-KEM with X25519 for defense-in-depth.

### Key Generation

```go
// Generate ML-KEM-768 hybrid key (recommended)
privateKey, err := cryptutil.GenerateMLKEMKey(rand.Reader, true)

// Generate ML-KEM-768 pure (no X25519)
privateKey, err := cryptutil.GenerateMLKEMKey(rand.Reader, false)

// Generate ML-KEM-1024 for higher security
privateKey, err := cryptutil.GenerateMLKEMKey1024(rand.Reader, true)
```

### Encryption and Decryption

```go
// Hybrid encryption (X25519 + ML-KEM)
ciphertext, err := cryptutil.HybridEncrypt(rand.Reader, plaintext, publicKey)

// Pure ML-KEM encryption
ciphertext, err := cryptutil.MLKEMEncrypt(rand.Reader, plaintext, publicKey)

// Decryption (auto-detects hybrid vs pure)
plaintext, err := cryptutil.MLKEMDecrypt(ciphertext, privateKey)
```

### Using ML-KEM with Bottles

```go
// ML-KEM keys work seamlessly with bottles
mlkemKey, _ := cryptutil.GenerateMLKEMKey(rand.Reader, true)

bottle := cryptutil.NewBottle([]byte("quantum-safe message"))
bottle.Encrypt(rand.Reader, mlkemKey.Public())

// Mixed recipients (classical + post-quantum)
bottle.Encrypt(rand.Reader, ecdsaKey.Public(), mlkemKey.Public())
```

### Key Serialization

```go
// Marshal to PKCS#8 (private) / PKIX (public)
privDER, err := privateKey.MarshalPKCS8PrivateKey()
pubDER, err := publicKey.MarshalPKIXPublicKey()

// Parse from DER
privateKey, err := cryptutil.ParseMLKEMPrivateKey(privDER)
publicKey, err := cryptutil.ParseMLKEMPublicKey(pubDER)
```

## ECDH Message Encryption

Simple encryption to ECDSA/ECDH keys, supporting TPM and HSM backends through the `ECDHHandler` interface.

```go
// Encrypt to an ECDH public key
ciphertext, err := cryptutil.ECDHEncrypt(rand.Reader, plaintext, ecdhPublicKey)

// Decrypt with private key (or any ECDHHandler)
plaintext, err := cryptutil.ECDHDecrypt(ciphertext, ecdhPrivateKey)
```

## IDCard

IDCards allow entities to declare sub-keys with specific purposes (signing, decryption) and manage key lifecycles.

```go
// Create an IDCard for a signing key
idcard, err := cryptutil.NewIDCard(signingKey.Public())

// Add metadata
idcard.Meta = map[string]string{"name": "Alice", "email": "alice@example.com"}

// Configure key purposes
idcard.SetKeyPurposes(signingKey.Public(), "sign", "decrypt")

// Add a dedicated encryption key
idcard.SetKeyPurposes(encryptionKey.Public(), "decrypt")
idcard.SetKeyDuration(encryptionKey.Public(), 365*24*time.Hour) // 1 year expiry

// Sign and serialize the IDCard
signedIDCard, err := idcard.Sign(rand.Reader, signingKey)

// Load and verify an IDCard
var loaded cryptutil.IDCard
err = loaded.UnmarshalBinary(signedIDCard)

// Check key purposes
err = loaded.TestKeyPurpose(someKey, "sign")
if err != nil {
    fmt.Println("Key not authorized for signing")
}

// Get all keys for a purpose
decryptKeys := loaded.GetKeys("decrypt")
```

## Keychain

Keychain provides secure storage for private keys, indexed by their public key.

```go
// Create a keychain
kc := cryptutil.NewKeychain()

// Add keys (supports ECDSA, Ed25519, RSA, ML-KEM)
kc.AddKey(ecdsaPrivateKey)
kc.AddKey(ed25519PrivateKey)
kc.AddKey(mlkemPrivateKey)

// Add multiple keys at once
kc.AddKeys(key1, key2, key3)

// Retrieve keys by public key
privateKey, err := kc.GetKey(publicKey)
signer, err := kc.GetSigner(publicKey)

// Sign with a specific key
signature, err := kc.Sign(rand.Reader, publicKey, message)

// Iterate over keys
for signer := range kc.Signers {
    fmt.Printf("Signer: %T\n", signer.Public())
}

// Use keychain with Opener
opener, err := cryptutil.NewOpener(kc)
```

## Membership

Memberships provide cryptographically signed group affiliations.

```go
// Create a membership
membership := cryptutil.NewMembership(memberIDCard, groupPublicKey)
membership.Info["role"] = "admin"

// Sign with group owner's key
err = membership.Sign(rand.Reader, groupOwnerKey)

// Verify membership
err = membership.Verify(groupIDCard)

// Add to IDCard
idcard.UpdateGroups([][]byte{membershipBytes})
```

## Signing and Verification

Low-level signing utilities that handle algorithm-specific requirements automatically.

```go
// Sign a message (hashing handled automatically)
signature, err := cryptutil.Sign(rand.Reader, privateKey, message)

// Verify a signature
err = cryptutil.Verify(publicKey, message, signature)
if err != nil {
    fmt.Println("Signature verification failed")
}
```

## Utility Functions

### PKIX Key Marshaling

Extended PKIX support including ML-KEM keys:

```go
// Marshal any public key to PKIX format
der, err := cryptutil.MarshalPKIXPublicKey(publicKey)

// Parse PKIX public key (supports ML-KEM)
publicKey, err := cryptutil.ParsePKIXPublicKey(der)
```

### Short Buffer Encryption

Encrypt small buffers (like AES keys) to various key types:

```go
// Encrypt a short buffer to any supported public key
encrypted, err := cryptutil.EncryptShortBuffer(rand.Reader, aesKey, recipientPublicKey)

// Decrypt
decrypted, err := cryptutil.DecryptShortBuffer(encrypted, recipientPrivateKey)
```

### Memory Clearing

Securely clear sensitive data from memory:

```go
privateKeyBytes := make([]byte, 32)
defer cryptutil.MemClr(privateKeyBytes)
```

### Hashing

Helper for single or multi-level hashing:

```go
// Single hash
digest := cryptutil.Hash(data, sha256.New)

// Multi-level hash (hash of hash)
digest := cryptutil.Hash(data, sha256.New, sha256.New)
```

## Supported Key Types

| Type | Signing | Encryption | Post-Quantum |
|------|---------|------------|--------------|
| ECDSA (P-256, P-384, P-521) | ✓ | ✓ (via ECDH) | ✗ |
| Ed25519 | ✓ | ✓ (via X25519) | ✗ |
| RSA | ✓ | ✓ | ✗ |
| ML-KEM-768 | ✗ | ✓ | ✓ |
| ML-KEM-1024 | ✗ | ✓ | ✓ |
| ML-KEM + X25519 (Hybrid) | ✗ | ✓ | ✓ |

## Error Handling

```go
var (
    ErrNoAppropriateKey   // No key available to decrypt
    ErrVerifyFailed       // Signature verification failed
    ErrKeyNotFound        // Key not found in keychain/IDCard
    ErrGroupNotFound      // Group not found in IDCard
    ErrKeyUnfit           // Key not authorized for the operation
    ErrEncryptNoRecipient // No valid recipient for encryption
)
```

## License

See [LICENSE](LICENSE) file.
