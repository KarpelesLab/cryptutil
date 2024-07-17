package cryptutil

// MemClr is a simple function that will clear a buffer in order to make it easier to
// reset memory storing private keys on defer.
func MemClr(b []byte) {
	for n := range b {
		b[n] = 0
	}
}
