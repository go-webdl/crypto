package p256

import "math/big"

// BytesToPoint maps a 32 bytes data into a point on the P256 curve using
// the Koblitz conversion algorithm. It may return nil if conversion fails.
// It can retrun nil with probability 64.645%.
func BytesToPoint(p []byte) (x *big.Int, y *big.Int) {
	u := new(big.Int).SetBytes(p)

	// t = (u^3 - 3 * u + b) MOD q
	t := new(big.Int).Mul(u, u)
	t.Mul(t, u)

	threeU := new(big.Int).Lsh(u, 1)
	threeU.Add(threeU, u)

	t.Sub(t, threeU)
	t.Add(t, Curve.Params().B)

	// Find v such that v^2 = t MOD q
	v := new(big.Int).ModSqrt(t, Curve.Params().P)

	if v == nil {
		return nil, nil
	}

	return u, v
}
