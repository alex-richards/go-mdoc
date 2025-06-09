package cipher_suite

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"io"

	"github.com/alex-richards/go-mdoc"
	mdocecdh "github.com/alex-richards/go-mdoc/cipher_suite/ecdh"
	mdocecdsa "github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	mdoced25519 "github.com/alex-richards/go-mdoc/cipher_suite/ed25519"
	mdoced448 "github.com/alex-richards/go-mdoc/cipher_suite/ed448"
	mdocx448 "github.com/alex-richards/go-mdoc/cipher_suite/x448"
	"github.com/cloudflare/circl/dh/x448"
)

var (
	ErrUnsupportedPrivateKey = errors.New("mdoc: unsupported private key")
)

func NewPrivateKey(curve mdoc.Curve, privateKey crypto.PrivateKey) (*mdoc.PrivateKey, error) {
	switch pk := privateKey.(type) {
	case ecdsa.PrivateKey:
		return mdocecdsa.NewPrivateKey(&pk)
	case *ecdsa.PrivateKey:
		return mdocecdsa.NewPrivateKey(pk)
	case ed25519.PrivateKey:
		return mdoced25519.NewPrivateKey(pk)
	case ecdh.PrivateKey:
		return mdocecdh.NewPrivateKey(&pk)
	case *ecdh.PrivateKey:
		return mdocecdh.NewPrivateKey(pk)
	case x448.Key:
		return mdocx448.NewPrivateKey(&pk)
	case *x448.Key:
		return mdocx448.NewPrivateKey(pk)
	default:
		return nil, ErrUnsupportedPrivateKey
	}
}

func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve, sign bool) (*mdoc.PrivateKey, error) {
	if sign {
		switch curve {
		case mdoc.CurveP256, mdoc.CurveP384, mdoc.CurveP521:
			return mdocecdsa.GeneratePrivateKey(rand, curve)
		case mdoc.CurveEd25519:
			return mdoced25519.GeneratePrivateKey(rand)
		case mdoc.CurveEd448:
			return mdoced448.GeneratePrivateKey(rand)
		}
	} else {
		switch curve {
		case mdoc.CurveP256, mdoc.CurveP384, mdoc.CurveP521, mdoc.CurveX25519:
			return mdocecdh.GeneratePrivateKey(rand, curve)
		case mdoc.CurveX448:
			return mdocx448.GeneratePrivateKey(rand)
		}
	}

	return nil, mdoc.ErrUnsupportedCurve
}
