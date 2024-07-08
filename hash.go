package cryptutil

import "hash"

// Hash is a helper function to perform hashes on buffers, including multi-level hashing
func Hash(b []byte, alg ...func() hash.Hash) []byte {
	for _, a := range alg {
		h := a()
		h.Write(b)
		b = h.Sum(nil)
	}
	return b
}
