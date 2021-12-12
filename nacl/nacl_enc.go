package nacl

import (
	cryptorand "crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

const EncryptOverhead = 40

var ErrDecrypt = errors.New("failed to decrypt")

func (key *Key) Encrypt(out, plaintext []byte, rand io.Reader) (ciphertext []byte, err error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	nonce := new([24]byte)
	if _, err = io.ReadFull(rand, (*nonce)[:]); err != nil {
		return
	}
	out = append(out, (*nonce)[:]...)
	ciphertext = secretbox.Seal(out, plaintext, nonce, key.PrivKey)
	return
}

func (key *Key) Decrypt(out, ciphertext []byte) (plaintext []byte, err error) {
	var ok bool
	nonce := new([24]byte)
	copy((*nonce)[:], ciphertext[:24])
	if plaintext, ok = secretbox.Open(out, ciphertext[24:], nonce, key.PrivKey); !ok {
		err = ErrDecrypt
		return
	}
	return
}
