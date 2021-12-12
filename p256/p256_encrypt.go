package p256

import (
	cryptorand "crypto/rand"
	"io"
	"math/big"
)

func (pubkey *Key) Encrypt(plaintext []byte, rand io.Reader) []byte {
	if rand == nil {
		rand = cryptorand.Reader
	}

	r, err := cryptorand.Int(rand, Curve.Params().N)
	if err != nil {
		panic(err)
	}

	Cx, Cy := Curve.ScalarBaseMult(r.Bytes())

	px, py := BytesToPoint(plaintext)
	if px == nil || py == nil {
		return nil
	}

	nKx, nKy := Curve.ScalarMult(pubkey.X, pubkey.Y, r.Bytes())

	Dx, Dy := Curve.Add(px, py, nKx, nKy)

	ciphertext := make([]byte, 128)
	copy(ciphertext[0:32], Cx.Bytes())
	copy(ciphertext[32:64], Cy.Bytes())
	copy(ciphertext[64:96], Dx.Bytes())
	copy(ciphertext[96:128], Dy.Bytes())

	return ciphertext
}

func (priv *Key) Decrypt(ciphertext []byte) []byte {
	Cx := new(big.Int).SetBytes(ciphertext[0:32])
	Cy := new(big.Int).SetBytes(ciphertext[32:64])
	Dx := new(big.Int).SetBytes(ciphertext[64:96])
	Dy := new(big.Int).SetBytes(ciphertext[96:128])

	kCx, kCy := Curve.ScalarMult(Cx, Cy, priv.D.Bytes())

	// Invert k * C => - k * C
	kCy.Neg(kCy)

	px, _ := Curve.Add(Dx, Dy, kCx, kCy)
	return px.Bytes()
}
