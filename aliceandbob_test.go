package cryptutil_test

import (
	"crypto/ecdh"
	"encoding/base64"
)

var (
	alice = must(ecdh.P256().NewPrivateKey(must(base64.RawURLEncoding.DecodeString("_J1nPevoYc3bYCs7htscdnPgregNasbZcufMTKkF3LI"))))
	bob   = must(ecdh.P256().NewPrivateKey(must(base64.RawURLEncoding.DecodeString("w9V4eOe1TdFpNaA-omztVs090w6hd8rPBT47e_gfF-Y"))))
)
