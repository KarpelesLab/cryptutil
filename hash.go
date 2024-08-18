package cryptutil

import "hash"

// Hash is a helper function to perform hashes on buffers, including multi-level hashing
func Hash(b []byte, alg ...func() hash.Hash) []byte {
	var x []byte
	for _, a := range alg {
		h := a()
		h.Write(b)
		b = h.Sum(x)
		x = b[:0]
	}
	return b
}
