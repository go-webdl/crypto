package sha1

import "crypto/sha1"

func SHA1(b []byte) []byte {
	m := sha1.Sum(b)
	return m[:]
}
