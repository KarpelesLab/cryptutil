package cryptutil

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
)

// ML-KEM OIDs as defined by NIST
// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
var (
	oidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}

	// OID for X25519 (reserved for future use)
	_ = asn1.ObjectIdentifier{1, 3, 101, 110}

	// Composite KEM OID (id-MLKEM768-X25519) - draft-ietf-lamps-pq-composite-kem
	// Using a placeholder OID under our own arc for now until standardized
	oidCompositeMLKEM768X25519  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 60545, 1, 1, 1}
	oidCompositeMLKEM1024X25519 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 60545, 1, 1, 2}
)

// MLKEMVariant specifies the ML-KEM parameter set.
type MLKEMVariant byte

const (
	MLKEM768  MLKEMVariant = 0 // ML-KEM-768 (recommended for most applications)
	MLKEM1024 MLKEMVariant = 1 // ML-KEM-1024 (higher security level)
)

// mlkemEncapsulator is an interface for ML-KEM encapsulation keys.
type mlkemEncapsulator interface {
	Encapsulate() (sharedKey, ciphertext []byte)
	Bytes() []byte
}

// mlkemDecapsulator is an interface for ML-KEM decapsulation keys.
type mlkemDecapsulator interface {
	Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
	Bytes() []byte
	EncapsulationKey() mlkemEncapsulator
}

// decapsulationKey768Wrapper wraps mlkem.DecapsulationKey768 to implement mlkemDecapsulator.
type decapsulationKey768Wrapper struct {
	key *mlkem.DecapsulationKey768
}

func (w *decapsulationKey768Wrapper) Decapsulate(ciphertext []byte) ([]byte, error) {
	return w.key.Decapsulate(ciphertext)
}

func (w *decapsulationKey768Wrapper) Bytes() []byte {
	return w.key.Bytes()
}

func (w *decapsulationKey768Wrapper) EncapsulationKey() mlkemEncapsulator {
	return w.key.EncapsulationKey()
}

// decapsulationKey1024Wrapper wraps mlkem.DecapsulationKey1024 to implement mlkemDecapsulator.
type decapsulationKey1024Wrapper struct {
	key *mlkem.DecapsulationKey1024
}

func (w *decapsulationKey1024Wrapper) Decapsulate(ciphertext []byte) ([]byte, error) {
	return w.key.Decapsulate(ciphertext)
}

func (w *decapsulationKey1024Wrapper) Bytes() []byte {
	return w.key.Bytes()
}

func (w *decapsulationKey1024Wrapper) EncapsulationKey() mlkemEncapsulator {
	return w.key.EncapsulationKey()
}

// MLKEMPublicKey wraps an ML-KEM encapsulation key with an optional X25519 key for hybrid mode.
// When X25519 is set, encryption uses hybrid mode (X25519 + ML-KEM) for defense-in-depth.
type MLKEMPublicKey struct {
	mlkem   mlkemEncapsulator
	X25519  *ecdh.PublicKey // optional, for hybrid mode
	variant MLKEMVariant
}

// MLKEMPrivateKey wraps an ML-KEM decapsulation key with an optional X25519 key for hybrid mode.
type MLKEMPrivateKey struct {
	mlkem   mlkemDecapsulator
	X25519  *ecdh.PrivateKey // optional, for hybrid mode
	variant MLKEMVariant
}

// Variant returns the ML-KEM variant (768 or 1024) for this key.
func (k *MLKEMPublicKey) Variant() MLKEMVariant {
	return k.variant
}

// Variant returns the ML-KEM variant (768 or 1024) for this key.
func (k *MLKEMPrivateKey) Variant() MLKEMVariant {
	return k.variant
}

// GenerateMLKEMKey generates a new ML-KEM-768 key pair. If hybrid is true, also generates an X25519 key pair.
// For ML-KEM-1024, use GenerateMLKEMKey1024.
func GenerateMLKEMKey(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	return GenerateMLKEMKey768(rand, hybrid)
}

// GenerateMLKEMKey768 generates a new ML-KEM-768 key pair. If hybrid is true, also generates an X25519 key pair.
func GenerateMLKEMKey768(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 key: %w", err)
	}

	priv := &MLKEMPrivateKey{
		mlkem:   &decapsulationKey768Wrapper{dk},
		variant: MLKEM768,
	}

	if hybrid {
		x25519Priv, err := ecdh.X25519().GenerateKey(rand)
		if err != nil {
			return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
		}
		priv.X25519 = x25519Priv
	}

	return priv, nil
}

// GenerateMLKEMKey1024 generates a new ML-KEM-1024 key pair. If hybrid is true, also generates an X25519 key pair.
func GenerateMLKEMKey1024(rand io.Reader, hybrid bool) (*MLKEMPrivateKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-1024 key: %w", err)
	}

	priv := &MLKEMPrivateKey{
		mlkem:   &decapsulationKey1024Wrapper{dk},
		variant: MLKEM1024,
	}

	if hybrid {
		x25519Priv, err := ecdh.X25519().GenerateKey(rand)
		if err != nil {
			return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
		}
		priv.X25519 = x25519Priv
	}

	return priv, nil
}

// Public returns the public key for this private key as crypto.PublicKey.
// This implements the PrivateKey interface.
func (k *MLKEMPrivateKey) Public() crypto.PublicKey {
	return k.MLKEMPublic()
}

// MLKEMPublic returns the typed ML-KEM public key for this private key.
func (k *MLKEMPrivateKey) MLKEMPublic() *MLKEMPublicKey {
	pub := &MLKEMPublicKey{
		mlkem:   k.mlkem.EncapsulationKey(),
		variant: k.variant,
	}
	if k.X25519 != nil {
		pub.X25519 = k.X25519.PublicKey()
	}
	return pub
}

// IsHybrid returns true if this is a hybrid key (X25519 + ML-KEM).
func (k *MLKEMPublicKey) IsHybrid() bool {
	return k.X25519 != nil
}

// IsHybrid returns true if this is a hybrid key (X25519 + ML-KEM).
func (k *MLKEMPrivateKey) IsHybrid() bool {
	return k.X25519 != nil
}

// Equal reports whether k and other have the same value.
func (k *MLKEMPublicKey) Equal(other crypto.PublicKey) bool {
	otherKey, ok := other.(*MLKEMPublicKey)
	if !ok {
		return false
	}
	if k.variant != otherKey.variant {
		return false
	}
	if !bytes.Equal(k.mlkem.Bytes(), otherKey.mlkem.Bytes()) {
		return false
	}
	if k.IsHybrid() != otherKey.IsHybrid() {
		return false
	}
	if k.IsHybrid() && !k.X25519.Equal(otherKey.X25519) {
		return false
	}
	return true
}

// PKIX encoding structures

// pkixPublicKey represents the ASN.1 structure for SubjectPublicKeyInfo
type pkixPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// compositePublicKey represents a composite public key (for hybrid mode)
type compositePublicKey struct {
	Keys []asn1.RawValue `asn1:"sequence"`
}

// MarshalPKIXPublicKey marshals an MLKEMPublicKey to PKIX/ASN.1 DER format.
// For hybrid keys, it uses a composite key format.
func (k *MLKEMPublicKey) MarshalPKIXPublicKey() ([]byte, error) {
	if k.IsHybrid() {
		return k.marshalCompositePKIX()
	}
	return k.marshalPurePKIX()
}

func (k *MLKEMPublicKey) marshalPurePKIX() ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch k.variant {
	case MLKEM768:
		oid = oidMLKEM768
	case MLKEM1024:
		oid = oidMLKEM1024
	default:
		return nil, fmt.Errorf("unknown ML-KEM variant: %d", k.variant)
	}

	spki := pkixPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes:     k.mlkem.Bytes(),
			BitLength: len(k.mlkem.Bytes()) * 8,
		},
	}

	return asn1.Marshal(spki)
}

func (k *MLKEMPublicKey) marshalCompositePKIX() ([]byte, error) {
	// Get the composite OID based on variant
	var compositeOID asn1.ObjectIdentifier
	switch k.variant {
	case MLKEM768:
		compositeOID = oidCompositeMLKEM768X25519
	case MLKEM1024:
		compositeOID = oidCompositeMLKEM1024X25519
	default:
		return nil, fmt.Errorf("unknown ML-KEM variant: %d", k.variant)
	}

	// Marshal X25519 public key
	x25519Bytes := k.X25519.Bytes()

	// Marshal ML-KEM public key
	mlkemBytes := k.mlkem.Bytes()

	// Create composite public key: SEQUENCE { x25519Key, mlkemKey }
	// Each component is wrapped as a BIT STRING
	x25519BitString := asn1.BitString{Bytes: x25519Bytes, BitLength: len(x25519Bytes) * 8}
	mlkemBitString := asn1.BitString{Bytes: mlkemBytes, BitLength: len(mlkemBytes) * 8}

	x25519Raw, err := asn1.Marshal(x25519BitString)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal X25519 component: %w", err)
	}
	mlkemRaw, err := asn1.Marshal(mlkemBitString)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM component: %w", err)
	}

	composite := compositePublicKey{
		Keys: []asn1.RawValue{
			{FullBytes: x25519Raw},
			{FullBytes: mlkemRaw},
		},
	}

	compositeBytes, err := asn1.Marshal(composite)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal composite key: %w", err)
	}

	spki := pkixPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: compositeOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     compositeBytes,
			BitLength: len(compositeBytes) * 8,
		},
	}

	return asn1.Marshal(spki)
}

// ParseMLKEMPublicKey parses a PKIX-encoded ML-KEM public key.
func ParseMLKEMPublicKey(der []byte) (*MLKEMPublicKey, error) {
	var spki pkixPublicKey
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX structure: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after PKIX structure")
	}

	oid := spki.Algorithm.Algorithm

	// Check for pure ML-KEM keys
	if oid.Equal(oidMLKEM768) {
		ek, err := mlkem.NewEncapsulationKey768(spki.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-768 key: %w", err)
		}
		return &MLKEMPublicKey{
			mlkem:   ek,
			variant: MLKEM768,
		}, nil
	}

	if oid.Equal(oidMLKEM1024) {
		ek, err := mlkem.NewEncapsulationKey1024(spki.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-1024 key: %w", err)
		}
		return &MLKEMPublicKey{
			mlkem:   ek,
			variant: MLKEM1024,
		}, nil
	}

	// Check for composite keys
	if oid.Equal(oidCompositeMLKEM768X25519) {
		return parseCompositePublicKey(spki.PublicKey.Bytes, MLKEM768)
	}

	if oid.Equal(oidCompositeMLKEM1024X25519) {
		return parseCompositePublicKey(spki.PublicKey.Bytes, MLKEM1024)
	}

	return nil, fmt.Errorf("unknown ML-KEM OID: %v", oid)
}

func parseCompositePublicKey(data []byte, variant MLKEMVariant) (*MLKEMPublicKey, error) {
	var composite compositePublicKey
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite key structure: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after composite key")
	}
	if len(composite.Keys) != 2 {
		return nil, fmt.Errorf("composite key should have 2 components, got %d", len(composite.Keys))
	}

	// Parse X25519 component
	var x25519BitString asn1.BitString
	_, err = asn1.Unmarshal(composite.Keys[0].FullBytes, &x25519BitString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 component: %w", err)
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519BitString.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 public key: %w", err)
	}

	// Parse ML-KEM component
	var mlkemBitString asn1.BitString
	_, err = asn1.Unmarshal(composite.Keys[1].FullBytes, &mlkemBitString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-KEM component: %w", err)
	}

	var ek mlkemEncapsulator
	switch variant {
	case MLKEM768:
		key, err := mlkem.NewEncapsulationKey768(mlkemBitString.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ML-KEM-768 key: %w", err)
		}
		ek = key
	case MLKEM1024:
		key, err := mlkem.NewEncapsulationKey1024(mlkemBitString.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ML-KEM-1024 key: %w", err)
		}
		ek = key
	}

	return &MLKEMPublicKey{
		mlkem:   ek,
		X25519:  x25519Pub,
		variant: variant,
	}, nil
}

// PKCS#8 private key structures

type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type compositePrivateKey struct {
	Keys []asn1.RawValue `asn1:"sequence"`
}

// MarshalPKCS8PrivateKey marshals an MLKEMPrivateKey to PKCS#8/ASN.1 DER format.
func (k *MLKEMPrivateKey) MarshalPKCS8PrivateKey() ([]byte, error) {
	if k.IsHybrid() {
		return k.marshalCompositePKCS8()
	}
	return k.marshalPurePKCS8()
}

func (k *MLKEMPrivateKey) marshalPurePKCS8() ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch k.variant {
	case MLKEM768:
		oid = oidMLKEM768
	case MLKEM1024:
		oid = oidMLKEM1024
	default:
		return nil, fmt.Errorf("unknown ML-KEM variant: %d", k.variant)
	}

	pkcs8 := pkcs8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: k.mlkem.Bytes(),
	}

	return asn1.Marshal(pkcs8)
}

func (k *MLKEMPrivateKey) marshalCompositePKCS8() ([]byte, error) {
	var compositeOID asn1.ObjectIdentifier
	switch k.variant {
	case MLKEM768:
		compositeOID = oidCompositeMLKEM768X25519
	case MLKEM1024:
		compositeOID = oidCompositeMLKEM1024X25519
	default:
		return nil, fmt.Errorf("unknown ML-KEM variant: %d", k.variant)
	}

	// Marshal X25519 private key
	x25519Bytes := k.X25519.Bytes()

	// Marshal ML-KEM private key (seed)
	mlkemBytes := k.mlkem.Bytes()

	// Create composite: SEQUENCE { OCTET STRING, OCTET STRING }
	x25519Raw, err := asn1.Marshal(x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal X25519 component: %w", err)
	}
	mlkemRaw, err := asn1.Marshal(mlkemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-KEM component: %w", err)
	}

	composite := compositePrivateKey{
		Keys: []asn1.RawValue{
			{FullBytes: x25519Raw},
			{FullBytes: mlkemRaw},
		},
	}

	compositeBytes, err := asn1.Marshal(composite)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal composite key: %w", err)
	}

	pkcs8 := pkcs8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: compositeOID,
		},
		PrivateKey: compositeBytes,
	}

	return asn1.Marshal(pkcs8)
}

// ParseMLKEMPrivateKey parses a PKCS#8-encoded ML-KEM private key.
func ParseMLKEMPrivateKey(der []byte) (*MLKEMPrivateKey, error) {
	var pkcs8 pkcs8PrivateKey
	rest, err := asn1.Unmarshal(der, &pkcs8)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after PKCS#8 structure")
	}

	oid := pkcs8.Algorithm.Algorithm

	// Check for pure ML-KEM keys
	if oid.Equal(oidMLKEM768) {
		dk, err := mlkem.NewDecapsulationKey768(pkcs8.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-768 key: %w", err)
		}
		return &MLKEMPrivateKey{
			mlkem:   &decapsulationKey768Wrapper{dk},
			variant: MLKEM768,
		}, nil
	}

	if oid.Equal(oidMLKEM1024) {
		dk, err := mlkem.NewDecapsulationKey1024(pkcs8.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-1024 key: %w", err)
		}
		return &MLKEMPrivateKey{
			mlkem:   &decapsulationKey1024Wrapper{dk},
			variant: MLKEM1024,
		}, nil
	}

	// Check for composite keys
	if oid.Equal(oidCompositeMLKEM768X25519) {
		return parseCompositePrivateKey(pkcs8.PrivateKey, MLKEM768)
	}

	if oid.Equal(oidCompositeMLKEM1024X25519) {
		return parseCompositePrivateKey(pkcs8.PrivateKey, MLKEM1024)
	}

	return nil, fmt.Errorf("unknown ML-KEM OID: %v", oid)
}

func parseCompositePrivateKey(data []byte, variant MLKEMVariant) (*MLKEMPrivateKey, error) {
	var composite compositePrivateKey
	rest, err := asn1.Unmarshal(data, &composite)
	if err != nil {
		return nil, fmt.Errorf("failed to parse composite key structure: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after composite key")
	}
	if len(composite.Keys) != 2 {
		return nil, fmt.Errorf("composite key should have 2 components, got %d", len(composite.Keys))
	}

	// Parse X25519 component
	var x25519Bytes []byte
	_, err = asn1.Unmarshal(composite.Keys[0].FullBytes, &x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 component: %w", err)
	}
	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 private key: %w", err)
	}

	// Parse ML-KEM component
	var mlkemBytes []byte
	_, err = asn1.Unmarshal(composite.Keys[1].FullBytes, &mlkemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-KEM component: %w", err)
	}

	var dk mlkemDecapsulator
	switch variant {
	case MLKEM768:
		key, err := mlkem.NewDecapsulationKey768(mlkemBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ML-KEM-768 key: %w", err)
		}
		dk = &decapsulationKey768Wrapper{key}
	case MLKEM1024:
		key, err := mlkem.NewDecapsulationKey1024(mlkemBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ML-KEM-1024 key: %w", err)
		}
		dk = &decapsulationKey1024Wrapper{key}
	}

	return &MLKEMPrivateKey{
		mlkem:   dk,
		X25519:  x25519Priv,
		variant: variant,
	}, nil
}

// HybridEncrypt encrypts data using hybrid X25519 + ML-KEM mode.
// Format: <version=1><x25519 pubkey len><x25519 ephemeral pubkey><mlkem ciphertext len><mlkem ciphertext><nonce><encrypted data>
func HybridEncrypt(rnd io.Reader, data []byte, remote *MLKEMPublicKey) ([]byte, error) {
	if !remote.IsHybrid() {
		return nil, fmt.Errorf("remote key is not a hybrid key, use MLKEMEncrypt instead")
	}

	// Generate ephemeral X25519 key and perform ECDH
	ephemeralX25519, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	x25519Secret, err := ephemeralX25519.ECDH(remote.X25519)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH failed: %w", err)
	}
	defer MemClr(x25519Secret)

	// Perform ML-KEM encapsulation (returns sharedKey, ciphertext)
	mlkemSecret, mlkemCiphertext := remote.mlkem.Encapsulate()
	defer MemClr(mlkemSecret)

	// Combine shared secrets: SHA-256(x25519_secret || mlkem_secret)
	combinedSecret := combineSecrets(x25519Secret, mlkemSecret)
	defer MemClr(combinedSecret)

	// Encrypt data with AES-GCM
	algo, err := aes.NewCipher(combinedSecret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(algo)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rnd, nonce)
	if err != nil {
		return nil, err
	}

	// Marshal X25519 public key
	x25519Pub, err := MarshalPKIXPublicKey(ephemeralX25519.PublicKey())
	if err != nil {
		return nil, err
	}

	// Build output: version(1) + x25519 key len + x25519 key + mlkem ciphertext len + mlkem ciphertext + nonce + encrypted data
	final := &bytes.Buffer{}
	final.WriteByte(1) // version 1 = hybrid mode
	final.Write(binary.AppendUvarint(nil, uint64(len(x25519Pub))))
	final.Write(x25519Pub)
	final.Write(binary.AppendUvarint(nil, uint64(len(mlkemCiphertext))))
	final.Write(mlkemCiphertext)
	final.Write(nonce)
	final.Write(gcm.Seal(nil, nonce, data, nil))

	return final.Bytes(), nil
}

// MLKEMEncrypt encrypts data using pure ML-KEM mode (no hybrid).
// Format: <version=2><mlkem ciphertext len><mlkem ciphertext><nonce><encrypted data>
func MLKEMEncrypt(rnd io.Reader, data []byte, remote *MLKEMPublicKey) ([]byte, error) {
	if remote.IsHybrid() {
		return nil, fmt.Errorf("use HybridEncrypt for hybrid keys")
	}

	// Perform ML-KEM encapsulation (returns sharedKey, ciphertext)
	mlkemSecret, mlkemCiphertext := remote.mlkem.Encapsulate()
	defer MemClr(mlkemSecret)

	// Use ML-KEM secret directly (it's already 32 bytes)
	algo, err := aes.NewCipher(mlkemSecret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(algo)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rnd, nonce)
	if err != nil {
		return nil, err
	}

	// Build output: version(2) + mlkem ciphertext len + mlkem ciphertext + nonce + encrypted data
	final := &bytes.Buffer{}
	final.WriteByte(2) // version 2 = pure ML-KEM mode
	final.Write(binary.AppendUvarint(nil, uint64(len(mlkemCiphertext))))
	final.Write(mlkemCiphertext)
	final.Write(nonce)
	final.Write(gcm.Seal(nil, nonce, data, nil))

	return final.Bytes(), nil
}

// MLKEMDecrypt decrypts data encrypted with HybridEncrypt or MLKEMEncrypt.
func MLKEMDecrypt(data []byte, privateKey *MLKEMPrivateKey) ([]byte, error) {
	e := func(err error) error {
		if err == nil {
			return nil
		}
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("while decrypting ML-KEM message: %w", err)
	}

	buf := bytes.NewReader(data)
	vers, err := buf.ReadByte()
	if err != nil {
		return nil, e(err)
	}

	switch vers {
	case 1:
		// Hybrid mode: X25519 + ML-KEM
		if !privateKey.IsHybrid() {
			return nil, fmt.Errorf("cannot decrypt hybrid message with non-hybrid key")
		}

		// Read X25519 ephemeral public key
		x25519Len, err := binary.ReadUvarint(buf)
		if err != nil {
			return nil, e(err)
		}
		if x25519Len > 65536 {
			return nil, fmt.Errorf("X25519 public key too large: %d bytes", x25519Len)
		}
		x25519PubBytes := make([]byte, x25519Len)
		_, err = io.ReadFull(buf, x25519PubBytes)
		if err != nil {
			return nil, e(err)
		}

		x25519PubObj, err := ParsePKIXPublicKey(x25519PubBytes)
		if err != nil {
			return nil, e(err)
		}
		x25519Pub, ok := x25519PubObj.(*ecdh.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected X25519 public key, got %T", x25519PubObj)
		}

		// Perform X25519 ECDH
		x25519Secret, err := privateKey.X25519.ECDH(x25519Pub)
		if err != nil {
			return nil, e(err)
		}
		defer MemClr(x25519Secret)

		// Read ML-KEM ciphertext
		mlkemLen, err := binary.ReadUvarint(buf)
		if err != nil {
			return nil, e(err)
		}
		if mlkemLen > 65536 {
			return nil, fmt.Errorf("ML-KEM ciphertext too large: %d bytes", mlkemLen)
		}
		mlkemCiphertext := make([]byte, mlkemLen)
		_, err = io.ReadFull(buf, mlkemCiphertext)
		if err != nil {
			return nil, e(err)
		}

		// Perform ML-KEM decapsulation
		mlkemSecret, err := privateKey.mlkem.Decapsulate(mlkemCiphertext)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
		}
		defer MemClr(mlkemSecret)

		// Combine secrets
		combinedSecret := combineSecrets(x25519Secret, mlkemSecret)
		defer MemClr(combinedSecret)

		return decryptAESGCM(buf, combinedSecret)

	case 2:
		// Pure ML-KEM mode
		// Read ML-KEM ciphertext
		mlkemLen, err := binary.ReadUvarint(buf)
		if err != nil {
			return nil, e(err)
		}
		if mlkemLen > 65536 {
			return nil, fmt.Errorf("ML-KEM ciphertext too large: %d bytes", mlkemLen)
		}
		mlkemCiphertext := make([]byte, mlkemLen)
		_, err = io.ReadFull(buf, mlkemCiphertext)
		if err != nil {
			return nil, e(err)
		}

		// Perform ML-KEM decapsulation
		mlkemSecret, err := privateKey.mlkem.Decapsulate(mlkemCiphertext)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
		}
		defer MemClr(mlkemSecret)

		return decryptAESGCM(buf, mlkemSecret)

	default:
		return nil, fmt.Errorf("unsupported ML-KEM message version %d", vers)
	}
}

// combineSecrets combines two shared secrets using SHA-256.
func combineSecrets(s1, s2 []byte) []byte {
	h := sha256.New()
	h.Write(s1)
	h.Write(s2)
	return h.Sum(nil)
}

// decryptAESGCM decrypts the remaining data in the buffer using AES-GCM.
func decryptAESGCM(buf *bytes.Reader, key []byte) ([]byte, error) {
	algo, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(algo)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(buf, nonce)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	dat, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return gcm.Open(dat[:0], nonce, dat, nil)
}

// Legacy marshalling functions for backward compatibility
// These use a simpler binary format, prefer PKIX functions for new code.

// x25519KeySize is the size of an X25519 key (public or private).
const x25519KeySize = 32

// Flag bits for legacy serialization
const (
	mlkemFlagHybrid  byte = 0x01 // Key includes X25519 for hybrid mode
	mlkemFlagVariant byte = 0x02 // If set, variant is ML-KEM-1024; otherwise ML-KEM-768
)

// MarshalMLKEMPublicKey marshals an MLKEMPublicKey to a simple binary format.
// Deprecated: Use MarshalPKIXPublicKey for standard PKIX encoding.
func MarshalMLKEMPublicKey(k *MLKEMPublicKey) []byte {
	var flags byte
	if k.IsHybrid() {
		flags |= mlkemFlagHybrid
	}
	if k.variant == MLKEM1024 {
		flags |= mlkemFlagVariant
	}

	buf := &bytes.Buffer{}
	buf.WriteByte(flags)
	buf.Write(k.mlkem.Bytes())
	if k.IsHybrid() {
		buf.Write(k.X25519.Bytes())
	}
	return buf.Bytes()
}

// UnmarshalMLKEMPublicKey unmarshals an MLKEMPublicKey from simple binary format.
// Deprecated: Use ParseMLKEMPublicKey for standard PKIX encoding.
func UnmarshalMLKEMPublicKey(data []byte) (*MLKEMPublicKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ML-KEM public key")
	}

	flags := data[0]
	data = data[1:]
	isHybrid := flags&mlkemFlagHybrid != 0
	is1024 := flags&mlkemFlagVariant != 0

	var ek mlkemEncapsulator
	var variant MLKEMVariant
	var keySize int

	if is1024 {
		variant = MLKEM1024
		keySize = mlkem.EncapsulationKeySize1024
		if len(data) < keySize {
			return nil, fmt.Errorf("data too short for ML-KEM-1024 encapsulation key")
		}
		key, err := mlkem.NewEncapsulationKey1024(data[:keySize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-1024 encapsulation key: %w", err)
		}
		ek = key
	} else {
		variant = MLKEM768
		keySize = mlkem.EncapsulationKeySize768
		if len(data) < keySize {
			return nil, fmt.Errorf("data too short for ML-KEM-768 encapsulation key")
		}
		key, err := mlkem.NewEncapsulationKey768(data[:keySize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-768 encapsulation key: %w", err)
		}
		ek = key
	}
	data = data[keySize:]

	pub := &MLKEMPublicKey{
		mlkem:   ek,
		variant: variant,
	}

	if isHybrid {
		if len(data) < x25519KeySize {
			return nil, fmt.Errorf("data too short for X25519 public key in hybrid mode")
		}
		x25519Pub, err := ecdh.X25519().NewPublicKey(data[:x25519KeySize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse X25519 public key: %w", err)
		}
		pub.X25519 = x25519Pub
	}

	return pub, nil
}

// MarshalMLKEMPrivateKey marshals an MLKEMPrivateKey to a simple binary format.
// Deprecated: Use MarshalPKCS8PrivateKey for standard PKCS#8 encoding.
func MarshalMLKEMPrivateKey(k *MLKEMPrivateKey) []byte {
	var flags byte
	if k.IsHybrid() {
		flags |= mlkemFlagHybrid
	}
	if k.variant == MLKEM1024 {
		flags |= mlkemFlagVariant
	}

	buf := &bytes.Buffer{}
	buf.WriteByte(flags)
	buf.Write(k.mlkem.Bytes())
	if k.IsHybrid() {
		buf.Write(k.X25519.Bytes())
	}
	return buf.Bytes()
}

// UnmarshalMLKEMPrivateKey unmarshals an MLKEMPrivateKey from simple binary format.
// Deprecated: Use ParseMLKEMPrivateKey for standard PKCS#8 encoding.
func UnmarshalMLKEMPrivateKey(data []byte) (*MLKEMPrivateKey, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ML-KEM private key")
	}

	flags := data[0]
	data = data[1:]
	isHybrid := flags&mlkemFlagHybrid != 0
	is1024 := flags&mlkemFlagVariant != 0

	// Both ML-KEM-768 and ML-KEM-1024 use the same seed size
	if len(data) < mlkem.SeedSize {
		return nil, fmt.Errorf("data too short for ML-KEM decapsulation key seed")
	}

	var dk mlkemDecapsulator
	var variant MLKEMVariant

	if is1024 {
		variant = MLKEM1024
		key, err := mlkem.NewDecapsulationKey1024(data[:mlkem.SeedSize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-1024 decapsulation key: %w", err)
		}
		dk = &decapsulationKey1024Wrapper{key}
	} else {
		variant = MLKEM768
		key, err := mlkem.NewDecapsulationKey768(data[:mlkem.SeedSize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse ML-KEM-768 decapsulation key: %w", err)
		}
		dk = &decapsulationKey768Wrapper{key}
	}
	data = data[mlkem.SeedSize:]

	priv := &MLKEMPrivateKey{
		mlkem:   dk,
		variant: variant,
	}

	if isHybrid {
		if len(data) < x25519KeySize {
			return nil, fmt.Errorf("data too short for X25519 private key in hybrid mode")
		}
		x25519Priv, err := ecdh.X25519().NewPrivateKey(data[:x25519KeySize])
		if err != nil {
			return nil, fmt.Errorf("failed to parse X25519 private key: %w", err)
		}
		priv.X25519 = x25519Priv
	}

	return priv, nil
}
