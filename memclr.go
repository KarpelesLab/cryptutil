package cryptutil

func MemClr(b []byte) {
	for n := range b {
		b[n] = 0
	}
}
