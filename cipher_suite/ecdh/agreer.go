package ecdh

import (
	"crypto/ecdh"
	"github.com/alex-richards/go-mdoc"
	"io"
)

type Agreer struct {
	curve  mdoc.Curve
	agreer ecdh.PrivateKey
}

func NewAgreer(rand io.Reader, curve mdoc.Curve) (*Agreer, error) {
	var ecdhCurve ecdh.Curve
	switch curve {
	case mdoc.CurveP256:
		ecdhCurve = ecdh.P256()
	case mdoc.CurveP384:
		ecdhCurve = ecdh.P384()
	case mdoc.CurveP521:
		ecdhCurve = ecdh.P521()
	case mdoc.CurveX25519:
		ecdhCurve = ecdh.X25519()
	default:
		return nil, nil // TODO error
	}

	agreer, err := ecdhCurve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return &Agreer{
		curve,
		*agreer,
	}, nil
}

func (a *Agreer) Curve() mdoc.Curve {
	return a.curve
}

func (a *Agreer) Agree(deviceKey *mdoc.PublicKey) ([]byte, error) {
	remote, err := fromMDocPublicKey(deviceKey)
	if err != nil {
		return nil, err
	}

	return a.agreer.ECDH(remote)
}
