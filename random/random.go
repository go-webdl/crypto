package random

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand"

	"github.com/go-webdl/crypto/sha256"
)

func Seed(seed []byte) io.Reader {
	var seed64 int64
	if err := binary.Read(bytes.NewReader(sha256.SHA256(seed)), binary.BigEndian, &seed64); err != nil {
		panic(err)
	}
	return mathrand.New(mathrand.NewSource(seed64))
}

func RandomBytes(n uint, rand io.Reader) []byte {
	if rand == nil {
		rand = cryptorand.Reader
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
