package cryptutil_test

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Errorf("must assertion failed: %w", err))
	}
	return v
}

//log.Printf("privkey = %s", base64.RawURLEncoding.EncodeToString(must(x509.MarshalECPrivateKey(must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))))))

var (
	alice = must(x509.ParseECPrivateKey(must(base64.RawURLEncoding.DecodeString("MHcCAQEEIIaSb1TJIeVordec4nMPaRBMsoroc462mpeWDuMEhY1-oAoGCCqGSM49AwEHoUQDQgAE09oIghTDnluvtv0-NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE-KYA"))))
	bob   = must(x509.ParseECPrivateKey(must(base64.RawURLEncoding.DecodeString("MHcCAQEEIIPJmeofQddlqI3MNJEBcjEVhNjoR-aYpJXLa3X2q40koAoGCCqGSM49AwEHoUQDQgAEigRCfu95oGP9FNSLWoxhhCDEmgxYG8tMwlFItzAuV6W_fw0Og2BNG3yc0qOb-cEJjQKWRI9i_m1FUc97ajaTrg"))))
)
