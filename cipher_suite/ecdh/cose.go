package ecdh

import (
	"crypto/ecdh"

	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
)

func toPublicKey(public *ecdh.PublicKey) (*mdoc.PublicKey, error) {
	curve := cose.CurveReserved
	typ := cose.KeyTypeReserved
	alg := cose.AlgorithmReserved // TODO -27? go-cose ECDH support?
	switch public.Curve() {
	case ecdh.P256():
		curve = cose.CurveP256
		typ = cose.KeyTypeEC2
	case ecdh.P384():
		curve = cose.CurveP384
		typ = cose.KeyTypeEC2
	case ecdh.P521():
		curve = cose.CurveP521
		typ = cose.KeyTypeEC2
	case ecdh.X25519():
		curve = cose.CurveX25519
		typ = cose.KeyTypeOKP
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	bytes := public.Bytes()

	var params map[any]any
	if typ == cose.KeyTypeEC2 {
		size := (len(bytes) - 1) / 2

		if bytes[0] != 4 || size == 0 {
			panic("unexpected format")
		}

		x := make([]byte, size)
		copy(x, bytes[1:size+1])

		y := make([]byte, size)
		copy(y, bytes[1+size:])

		params = map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     x,
			cose.KeyLabelEC2Y:     y,
		}
	} else { // typ == cose.KeyTypeOKP
		params = map[any]any{
			cose.KeyLabelOKPCurve: curve,
			cose.KeyLabelOKPX:     bytes,
		}
	}

	return &mdoc.PublicKey{
		Type:      typ,
		Algorithm: alg,
		Params:    params,
	}, nil
}

func fromPublicKey(key *mdoc.PublicKey) (*ecdh.PublicKey, error) {
	switch key.Type {
	case cose.KeyTypeEC2:
		var curve ecdh.Curve
		switch key.Params[cose.KeyLabelEC2Curve] {
		case cose.CurveP256:
			curve = ecdh.P256()
		case cose.CurveP384:
			curve = ecdh.P384()
		case cose.CurveP521:
			curve = ecdh.P521()
		default:
			return nil, mdoc.ErrUnsupportedCurve
		}

		x, ok := key.Params[cose.KeyLabelEC2X].([]byte)
		if !ok {
			return nil, mdoc.ErrInvalidCOSE
		}

		y, ok := key.Params[cose.KeyLabelEC2Y].([]byte)
		if !ok {
			return nil, mdoc.ErrInvalidCOSE
		}

		bytes := make([]byte, 1+len(x)+len(y))
		bytes[0] = 4
		copy(bytes[1:], x)
		copy(bytes[1+len(x):], y)

		return curve.NewPublicKey(bytes)

	case cose.KeyTypeOKP:
		if key.Params[cose.KeyLabelOKPCurve] != cose.CurveX25519 {
			return nil, mdoc.ErrUnsupportedCurve
		}

		x, ok := key.Params[cose.KeyLabelOKPX].([]byte)
		if !ok {
			return nil, mdoc.ErrInvalidCOSE
		}

		return ecdh.X25519().NewPublicKey(x)

	default:
		return nil, mdoc.ErrUnsupportedCurve
	}
}
