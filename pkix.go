package cryptutil

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// ParsePKIXPublicKey parses a PKIX-encoded public key. It supports all key types
// supported by [crypto/x509.ParsePKIXPublicKey] as well as ML-KEM, ML-DSA, and SLH-DSA keys.
func ParsePKIXPublicKey(der []byte) (PublicKeyIntf, error) {
	// First, try to parse as ML-KEM or ML-DSA key by checking the OID
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err == nil {
		oid := spki.Algorithm.Algorithm
		if oid.Equal(oidMLKEM768) || oid.Equal(oidMLKEM1024) ||
			oid.Equal(oidCompositeMLKEM768X25519) || oid.Equal(oidCompositeMLKEM1024X25519) {
			return ParseMLKEMPublicKey(der)
		}
		if isMLDSAOID(oid) {
			pub, err := ParseMLDSAPublicKey(der)
			if err != nil {
				return nil, err
			}
			if pubIntf, ok := pub.(PublicKeyIntf); ok {
				return pubIntf, nil
			}
			return nil, fmt.Errorf("parsed ML-DSA key of type %T does not implement PublicKeyIntf", pub)
		}
		if isSLHDSAOID(oid) {
			pub, err := ParseSLHDSAPublicKey(der)
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
	}

	// Fall back to standard library for other key types
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	if pubIntf, ok := pub.(PublicKeyIntf); ok {
		return pubIntf, nil
	}
	return nil, fmt.Errorf("parsed key of type %T does not implement PublicKeyIntf", pub)
}

// MarshalPKIXPublicKey marshals a public key to PKIX/ASN.1 DER format. It supports
// all key types supported by [crypto/x509.MarshalPKIXPublicKey] as well as ML-KEM, ML-DSA, and SLH-DSA keys.
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if mlkemPub, ok := pub.(*MLKEMPublicKey); ok {
		return mlkemPub.MarshalPKIXPublicKey()
	}
	if isMLDSAPublicKey(pub) {
		return MarshalMLDSAPublicKey(pub)
	}
	if isSLHDSAPublicKey(pub) {
		return MarshalSLHDSAPublicKey(pub)
	}
	return x509.MarshalPKIXPublicKey(pub)
}
