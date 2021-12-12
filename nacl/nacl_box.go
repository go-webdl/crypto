package nacl

import (
	cryptorand "crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

var ErrOpen = errors.New("failed to open")

func Seal(out, plaintext []byte, recipientPubKey, senderPrivKey *Key, rand io.Reader) (ciphertext []byte, err error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	if senderPrivKey == nil {
		return box.SealAnonymous(out, plaintext, recipientPubKey.PubKey, rand)
	} else {
		if total := len(out) + 24 + box.Overhead + len(plaintext); cap(out) < total {
			original := out
			out = make([]byte, 0, total)
			out = append(out, original...)
		}
		nonce := new([24]byte)
		if _, err = io.ReadFull(rand, (*nonce)[:]); err != nil {
			return
		}
		out = append(out, (*nonce)[:]...)
		ciphertext = box.Seal(out, plaintext, nonce, recipientPubKey.PubKey, senderPrivKey.PrivKey)
		return
	}
}

func Open(out, ciphertext []byte, senderPubKey, recipientPrivKey *Key) (plaintext []byte, err error) {
	var ok bool
	if senderPubKey == nil {
		plaintext, ok = box.OpenAnonymous(out, ciphertext, recipientPrivKey.PubKey, recipientPrivKey.PrivKey)

	} else {
		nonce := new([24]byte)
		copy((*nonce)[:], ciphertext[:24])
		plaintext, ok = box.Open(out, ciphertext, nonce, senderPubKey.PubKey, recipientPrivKey.PrivKey)
	}
	if !ok {
		err = ErrOpen
	}
	return
}
