package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
)

func toPublicKey(key *ecdsa.PublicKey) (*mdoc.PublicKey, error) {
	curve := cose.CurveReserved
	alg := cose.AlgorithmReserved
	switch key.Curve {
	case elliptic.P256():
		curve = cose.CurveP256
		alg = cose.AlgorithmES256
	case elliptic.P384():
		curve = cose.CurveP384
		alg = cose.AlgorithmES384
	case elliptic.P521():
		curve = cose.CurveP521
		alg = cose.AlgorithmES512
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	size := (key.Params().BitSize + 7) / 8

	x := make([]byte, size)
	key.X.FillBytes(x)

	y := make([]byte, size)
	key.Y.FillBytes(y)

	return &mdoc.PublicKey{
		Type:      cose.KeyTypeEC2,
		Algorithm: alg,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     x,
			cose.KeyLabelEC2Y:     y,
		},
	}, nil
}
