package p256

import (
	"crypto/ecdsa"
	"io"
	"math/big"

	"github.com/go-webdl/crypto/random"
)

type Key ecdsa.PrivateKey

func New(rand io.Reader) *Key {
	return PrivKey(random.RandomBytes(0x20, rand))
}

func (key *Key) Bytes() []byte {
	b := make([]byte, 0x40)
	copy(b[0:0x20], key.X.Bytes())
	copy(b[0x20:0x40], key.Y.Bytes())
	return b
}

func PrivKey(D []byte) (priv *Key) {
	priv = (*Key)(&ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: Curve,
		},
		D: new(big.Int).SetBytes(D),
	})
	priv.X, priv.Y = Curve.ScalarBaseMult(D)
	return
}

func PubKey(XY []byte) (pubkey *Key) {
	pubkey = new(Key)
	pubkey.X = new(big.Int).SetBytes(XY[0:0x20])
	pubkey.Y = new(big.Int).SetBytes(XY[0x20:0x40])
	return
}
