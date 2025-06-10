package ecdh

import (
	"crypto/ecdh"
	"io"

	"github.com/alex-richards/go-mdoc"
)

// GeneratePrivateKey generates a new private key for use with go-mdoc.
func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve) (*mdoc.PrivateKey, error) {
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
		return nil, mdoc.ErrUnsupportedCurve
	}

	privateKey, err := c.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return newPrivateKey(curve, privateKey)
}

// NewPrivateKey wraps an existing private key for use with go-mdoc.
func NewPrivateKey(privateKey *ecdh.PrivateKey) (*mdoc.PrivateKey, error) {
	var curve mdoc.Curve
	switch privateKey.Curve() {
	case ecdh.P256():
		curve = mdoc.CurveP256
	case ecdh.P384():
		curve = mdoc.CurveP384
	case ecdh.P521():
		curve = mdoc.CurveP521
	case ecdh.X25519():
		curve = mdoc.CurveX25519
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	return newPrivateKey(curve, privateKey)
}

func newPrivateKey(curve mdoc.Curve, privateKey *ecdh.PrivateKey) (*mdoc.PrivateKey, error) {
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
