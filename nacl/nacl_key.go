package nacl

import (
	"io"

	"github.com/go-webdl/crypto/random"

	"golang.org/x/crypto/curve25519"
)

type Key struct {
	PrivKey *[32]byte
	PubKey  *[32]byte
}

func New(rand io.Reader) *Key {
	pri := random.RandomBytes(32, rand)
	// From https://cr.yp.to/ecdh.html
	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64
	return PrivKey(pri)
}

func (key *Key) Bytes() []byte {
	b := make([]byte, 64)
	copy(b[:32], (*key.PrivKey)[:])
	copy(b[32:], (*key.PubKey)[:])
	return b
}

func PubKey(b []byte) *Key {
	key := &Key{PubKey: new([32]byte)}
	copy((*key.PrivKey)[:], b[:32])
	return key
}

func PrivKey(b []byte) *Key {
	key := &Key{new([32]byte), new([32]byte)}
	copy((*key.PrivKey)[:], b[:32])
	curve25519.ScalarBaseMult(key.PubKey, key.PrivKey)
	return key
}
