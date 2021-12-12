package p256

import (
	"crypto/elliptic"
	"math/big"
)

// Pull some internal fetures out for easier field operations
type CurveField interface {
	elliptic.Curve
	Inverse(k *big.Int) *big.Int
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

var Curve = elliptic.P256().(CurveField)
