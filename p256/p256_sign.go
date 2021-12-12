package p256

import (
	cryptorand "crypto/rand"
	"io"
	"math/big"
)

func (priv *Key) Sign(digest []byte, rand io.Reader) []byte {
	var err error
	var Ax, s, t, r *big.Int

	if rand == nil {
		rand = cryptorand.Reader
	}

	m := new(big.Int).SetBytes(digest)

	for {
		for {
			r, err = cryptorand.Int(rand, Curve.Params().N)
			if err != nil {
				panic(err)
			}

			Ax, _ = Curve.ScalarBaseMult(r.Bytes())
			s = new(big.Int).Mod(Ax, Curve.Params().N)
			if s.Sign() != 0 {
				break
			}
		}

		t = new(big.Int).Mul(s, priv.D)
		t = t.Add(t, m)
		t = t.Mul(t, Curve.Inverse(r))
		t = t.Mod(t, Curve.Params().N)

		if t.Sign() != 0 {
			break
		}
	}

	sig := make([]byte, 64)
	copy(sig[0:32], s.Bytes())
	copy(sig[32:64], t.Bytes())
	return sig
}

func (pub *Key) Verify(digest, sig []byte) bool {
	e := new(big.Int).SetBytes(digest)
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])

	// See [NSA] 3.4.2
	N := Curve.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	w := Curve.Inverse(s)

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	x, y := Curve.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}
