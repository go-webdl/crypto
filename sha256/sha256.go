package sha256

import "crypto/sha256"

func SHA256(b []byte) []byte {
	m := sha256.Sum256(b)
	return m[:]
}
