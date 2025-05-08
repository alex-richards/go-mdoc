package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
)

func toMDocPublicKey(key *ecdsa.PublicKey) (*mdoc.PublicKey, error) {
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
		return nil, ErrUnsupportedCurve
	}

	size := (key.Params().BitSize) + 7/8

	x := key.X.Bytes()
	xLen := len(x)

	y := key.Y.Bytes()
	yLen := len(y)

	if xLen > size || yLen > size {
		return nil, nil // TODO error
	}

	coseX := make([]byte, size)
	copy(coseX[size-xLen:], x)

	coseY := make([]byte, size)
	copy(coseY[size-yLen:], y)

	return &mdoc.PublicKey{
		Type:      cose.KeyTypeEC2,
		Algorithm: alg,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     coseX,
			cose.KeyLabelEC2Y:     coseY,
		},
	}, nil
}

func fromMDocPublicDeviceKey(key *mdoc.PublicKey) (*ecdsa.PublicKey, error) {
	panic("todo") // TOOD
}
