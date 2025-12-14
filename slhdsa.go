package cryptutil

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/KarpelesLab/slhdsa"
)

// SLH-DSA OIDs from NIST's Computer Security Objects Register
// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
var (
	// SHA2-based parameter sets
	oidSLHDSA_SHA2_128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}
	oidSLHDSA_SHA2_128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}
	oidSLHDSA_SHA2_192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}
	oidSLHDSA_SHA2_192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}
	oidSLHDSA_SHA2_256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}
	oidSLHDSA_SHA2_256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}

	// SHAKE-based parameter sets
	oidSLHDSA_SHAKE_128s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}
	oidSLHDSA_SHAKE_128f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}
	oidSLHDSA_SHAKE_192s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}
	oidSLHDSA_SHAKE_192f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}
	oidSLHDSA_SHAKE_256s = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}
	oidSLHDSA_SHAKE_256f = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}
)

// slhdsaParamsToOID maps SLH-DSA parameter sets to their OIDs
var slhdsaParamsToOID = map[*slhdsa.Params]asn1.ObjectIdentifier{
	slhdsa.SHA2_128s:  oidSLHDSA_SHA2_128s,
	slhdsa.SHA2_128f:  oidSLHDSA_SHA2_128f,
	slhdsa.SHA2_192s:  oidSLHDSA_SHA2_192s,
	slhdsa.SHA2_192f:  oidSLHDSA_SHA2_192f,
	slhdsa.SHA2_256s:  oidSLHDSA_SHA2_256s,
	slhdsa.SHA2_256f:  oidSLHDSA_SHA2_256f,
	slhdsa.SHAKE_128s: oidSLHDSA_SHAKE_128s,
	slhdsa.SHAKE_128f: oidSLHDSA_SHAKE_128f,
	slhdsa.SHAKE_192s: oidSLHDSA_SHAKE_192s,
	slhdsa.SHAKE_192f: oidSLHDSA_SHAKE_192f,
	slhdsa.SHAKE_256s: oidSLHDSA_SHAKE_256s,
	slhdsa.SHAKE_256f: oidSLHDSA_SHAKE_256f,
}

// slhdsaOIDToParams maps OIDs to SLH-DSA parameter sets
var slhdsaOIDToParams = map[string]*slhdsa.Params{
	oidSLHDSA_SHA2_128s.String():  slhdsa.SHA2_128s,
	oidSLHDSA_SHA2_128f.String():  slhdsa.SHA2_128f,
	oidSLHDSA_SHA2_192s.String():  slhdsa.SHA2_192s,
	oidSLHDSA_SHA2_192f.String():  slhdsa.SHA2_192f,
	oidSLHDSA_SHA2_256s.String():  slhdsa.SHA2_256s,
	oidSLHDSA_SHA2_256f.String():  slhdsa.SHA2_256f,
	oidSLHDSA_SHAKE_128s.String(): slhdsa.SHAKE_128s,
	oidSLHDSA_SHAKE_128f.String(): slhdsa.SHAKE_128f,
	oidSLHDSA_SHAKE_192s.String(): slhdsa.SHAKE_192s,
	oidSLHDSA_SHAKE_192f.String(): slhdsa.SHAKE_192f,
	oidSLHDSA_SHAKE_256s.String(): slhdsa.SHAKE_256s,
	oidSLHDSA_SHAKE_256f.String(): slhdsa.SHAKE_256f,
}

// isSLHDSAPublicKey returns true if the given key is an SLH-DSA public key
func isSLHDSAPublicKey(key crypto.PublicKey) bool {
	_, ok := key.(*slhdsa.PublicKey)
	return ok
}

// MarshalSLHDSAPublicKey marshals an SLH-DSA public key to PKIX/ASN.1 DER format.
func MarshalSLHDSAPublicKey(pub crypto.PublicKey) ([]byte, error) {
	pk, ok := pub.(*slhdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported SLH-DSA public key type: %T", pub)
	}

	oid, ok := slhdsaParamsToOID[pk.Params()]
	if !ok {
		return nil, fmt.Errorf("unknown SLH-DSA parameter set: %s", pk.Params().String())
	}

	keyBytes := pk.Bytes()
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

// ParseSLHDSAPublicKey parses a PKIX-encoded SLH-DSA public key.
func ParseSLHDSAPublicKey(der []byte) (*slhdsa.PublicKey, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("failed to parse PKIX structure: %w", err)
	}

	params, ok := slhdsaOIDToParams[spki.Algorithm.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("unknown SLH-DSA OID: %v", spki.Algorithm.Algorithm)
	}

	return slhdsa.NewPublicKey(params, spki.PublicKey.Bytes)
}

// slhdsaPkcs8 is the ASN.1 structure for PKCS#8 private keys
type slhdsaPkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// MarshalSLHDSAPrivateKey marshals an SLH-DSA private key to PKCS#8/ASN.1 DER format.
func MarshalSLHDSAPrivateKey(key *slhdsa.PrivateKey) ([]byte, error) {
	oid, ok := slhdsaParamsToOID[key.Params()]
	if !ok {
		return nil, fmt.Errorf("unknown SLH-DSA parameter set: %s", key.Params().String())
	}

	keyBytes := key.Bytes()

	// Wrap the key bytes in an OCTET STRING
	privKeyOctetString, err := asn1.Marshal(keyBytes)
	if err != nil {
		return nil, err
	}

	pkcs8 := slhdsaPkcs8{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: privKeyOctetString,
	}

	return asn1.Marshal(pkcs8)
}

// ParseSLHDSAPrivateKey parses a PKCS#8-encoded SLH-DSA private key.
func ParseSLHDSAPrivateKey(der []byte) (*slhdsa.PrivateKey, error) {
	var pkcs8 slhdsaPkcs8
	if _, err := asn1.Unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 structure: %w", err)
	}

	// Unwrap the OCTET STRING
	var keyBytes []byte
	if _, err := asn1.Unmarshal(pkcs8.PrivateKey, &keyBytes); err != nil {
		return nil, fmt.Errorf("failed to parse private key bytes: %w", err)
	}

	params, ok := slhdsaOIDToParams[pkcs8.Algorithm.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("unknown SLH-DSA OID: %v", pkcs8.Algorithm.Algorithm)
	}

	return slhdsa.NewPrivateKey(params, keyBytes)
}

// slhdsaVerify verifies an SLH-DSA signature
func slhdsaVerify(pub *slhdsa.PublicKey, msg, sig []byte, opts ...crypto.SignerOpts) error {
	var context []byte
	if opt := getSignerOpt[slhdsa.Options](opts); opt != nil {
		context = opt.Context
	}

	if !pub.Verify(sig, msg, context) {
		return ErrVerifyFailed
	}
	return nil
}

// isSLHDSAOID returns true if the OID is an SLH-DSA OID
func isSLHDSAOID(oid asn1.ObjectIdentifier) bool {
	_, ok := slhdsaOIDToParams[oid.String()]
	return ok
}
