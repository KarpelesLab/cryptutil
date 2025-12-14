package cryptutil

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/KarpelesLab/mldsa"
)

// ML-DSA OIDs from NIST's Computer Security Objects Register
var (
	oidMLDSA44 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 4}
	oidMLDSA65 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5}
	oidMLDSA87 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 7}
)

// MLDSAVariant specifies the ML-DSA parameter set.
type MLDSAVariant byte

const (
	MLDSA44 MLDSAVariant = 0 // ML-DSA-44 (NIST security level 2)
	MLDSA65 MLDSAVariant = 1 // ML-DSA-65 (NIST security level 3)
	MLDSA87 MLDSAVariant = 2 // ML-DSA-87 (NIST security level 5)
)

// isMLDSAPublicKey returns true if the given key is an ML-DSA public key
func isMLDSAPublicKey(key crypto.PublicKey) bool {
	switch key.(type) {
	case *mldsa.PublicKey44, *mldsa.PublicKey65, *mldsa.PublicKey87:
		return true
	default:
		return false
	}
}

// MarshalMLDSAPublicKey marshals an ML-DSA public key to PKIX/ASN.1 DER format.
func MarshalMLDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var keyBytes []byte

	switch k := pub.(type) {
	case *mldsa.PublicKey44:
		oid = oidMLDSA44
		keyBytes = k.Bytes()
	case *mldsa.PublicKey65:
		oid = oidMLDSA65
		keyBytes = k.Bytes()
	case *mldsa.PublicKey87:
		oid = oidMLDSA87
		keyBytes = k.Bytes()
	default:
		return nil, fmt.Errorf("unsupported ML-DSA public key type: %T", pub)
	}

	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes:     keyBytes,
			BitLength: len(keyBytes) * 8,
		},
	}

	return asn1.Marshal(spki)
}

// ParseMLDSAPublicKey parses a PKIX-encoded ML-DSA public key.
func ParseMLDSAPublicKey(der []byte) (crypto.PublicKey, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse PKIX structure: %w", err)
	}

	oid := spki.Algorithm.Algorithm
	keyBytes := spki.PublicKey.Bytes

	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.NewPublicKey44(keyBytes)
	case oid.Equal(oidMLDSA65):
		return mldsa.NewPublicKey65(keyBytes)
	case oid.Equal(oidMLDSA87):
		return mldsa.NewPublicKey87(keyBytes)
	default:
		return nil, fmt.Errorf("unknown ML-DSA OID: %v", oid)
	}
}

// pkcs8 is the ASN.1 structure for PKCS#8 private keys
type mldsaPkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// MarshalMLDSAPrivateKey marshals an ML-DSA private key to PKCS#8/ASN.1 DER format.
func MarshalMLDSAPrivateKey(key crypto.Signer) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var keyBytes []byte

	switch k := key.(type) {
	case *mldsa.Key44:
		oid = oidMLDSA44
		keyBytes = k.Bytes() // seed
	case *mldsa.Key65:
		oid = oidMLDSA65
		keyBytes = k.Bytes() // seed
	case *mldsa.Key87:
		oid = oidMLDSA87
		keyBytes = k.Bytes() // seed
	case *mldsa.PrivateKey44:
		oid = oidMLDSA44
		keyBytes = k.Bytes() // full private key
	case *mldsa.PrivateKey65:
		oid = oidMLDSA65
		keyBytes = k.Bytes() // full private key
	case *mldsa.PrivateKey87:
		oid = oidMLDSA87
		keyBytes = k.Bytes() // full private key
	default:
		return nil, fmt.Errorf("unsupported ML-DSA private key type: %T", key)
	}

	// Wrap the key bytes in an OCTET STRING
	privKeyOctetString, err := asn1.Marshal(keyBytes)
	if err != nil {
		return nil, err
	}

	pkcs8 := mldsaPkcs8{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: privKeyOctetString,
	}

	return asn1.Marshal(pkcs8)
}

// ParseMLDSAPrivateKey parses a PKCS#8-encoded ML-DSA private key.
func ParseMLDSAPrivateKey(der []byte) (crypto.Signer, error) {
	var pkcs8 mldsaPkcs8
	if _, err := asn1.Unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}

	// Unwrap the OCTET STRING
	var keyBytes []byte
	if _, err := asn1.Unmarshal(pkcs8.PrivateKey, &keyBytes); err != nil {
		return nil, fmt.Errorf("failed to parse private key bytes: %w", err)
	}

	oid := pkcs8.Algorithm.Algorithm

	switch {
	case oid.Equal(oidMLDSA44):
		// Check if it's a seed (32 bytes) or full private key
		if len(keyBytes) == mldsa.SeedSize {
			return mldsa.NewKey44(keyBytes)
		}
		return mldsa.NewPrivateKey44(keyBytes)
	case oid.Equal(oidMLDSA65):
		if len(keyBytes) == mldsa.SeedSize {
			return mldsa.NewKey65(keyBytes)
		}
		return mldsa.NewPrivateKey65(keyBytes)
	case oid.Equal(oidMLDSA87):
		if len(keyBytes) == mldsa.SeedSize {
			return mldsa.NewKey87(keyBytes)
		}
		return mldsa.NewPrivateKey87(keyBytes)
	default:
		return nil, fmt.Errorf("unknown ML-DSA OID: %v", oid)
	}
}

// mldsaVerify verifies an ML-DSA signature
func mldsaVerify(pub crypto.PublicKey, msg, sig []byte, opts ...crypto.SignerOpts) error {
	var context []byte
	if opt := getSignerOpt[mldsa.SignerOpts](opts); opt != nil {
		context = opt.Context
	}

	var valid bool
	switch k := pub.(type) {
	case *mldsa.PublicKey44:
		valid = k.Verify(sig, msg, context)
	case *mldsa.PublicKey65:
		valid = k.Verify(sig, msg, context)
	case *mldsa.PublicKey87:
		valid = k.Verify(sig, msg, context)
	default:
		return fmt.Errorf("unsupported ML-DSA public key type: %T", pub)
	}

	if !valid {
		return ErrVerifyFailed
	}
	return nil
}

// isMLDSAOID returns true if the OID is an ML-DSA OID
func isMLDSAOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidMLDSA44) || oid.Equal(oidMLDSA65) || oid.Equal(oidMLDSA87)
}
