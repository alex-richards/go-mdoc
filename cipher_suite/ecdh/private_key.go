package ecdh

import (
	"crypto/ecdh"
	"io"

	"github.com/alex-richards/go-mdoc"
)

func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve) (*mdoc.PrivateKey, error) {
	privateKey, err := newPrivateKey(rand, curve)
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(curve, privateKey)
}

func NewPrivateKey(curve mdoc.Curve, privateKey *ecdh.PrivateKey) (*mdoc.PrivateKey, error) {
	publicKey, err := toPublicKey(privateKey.PublicKey())
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    nil,
		Agreer:    &agreer{curve, privateKey},
		PublicKey: *publicKey,
	}, nil
}

func newPrivateKey(rand io.Reader, curve mdoc.Curve) (*ecdh.PrivateKey, error) {
	var c ecdh.Curve
	switch curve {
	case mdoc.CurveP256:
		c = ecdh.P256()
	case mdoc.CurveP384:
		c = ecdh.P384()
	case mdoc.CurveP521:
		c = ecdh.P521()
	case mdoc.CurveX25519:
		c = ecdh.X25519()
	default:
		return nil, nil // TODO error
	}

	key, err := c.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return key, nil
}

type agreer struct {
	curve      mdoc.Curve
	privateKey *ecdh.PrivateKey
}

func (a *agreer) Curve() mdoc.Curve {
	return a.curve
}

func (a *agreer) Agree(deviceKey *mdoc.PublicKey) ([]byte, error) {
	remote, err := fromPublicKey(deviceKey)
	if err != nil {
		return nil, err
	}

	return a.privateKey.ECDH(remote)
}
