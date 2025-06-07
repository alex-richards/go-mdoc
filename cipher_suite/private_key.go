package cipher_suite

import (
	"crypto"
	"errors"
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdh"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	"github.com/alex-richards/go-mdoc/cipher_suite/ed25519"
	"github.com/alex-richards/go-mdoc/cipher_suite/ed448"
	"github.com/alex-richards/go-mdoc/cipher_suite/x448"
)

func NewPrivateKey(curve mdoc.Curve, signer crypto.Signer) (*mdoc.PrivateKey, error) {
	return nil, errors.New("TODO") // TODO
}

func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve, sign bool) (*mdoc.PrivateKey, error) {
	if sign {
		switch curve {
		case mdoc.CurveP256, mdoc.CurveP384, mdoc.CurveP521:
			return ecdsa.GeneratePrivateKey(rand, curve)
		case mdoc.CurveEd25519:
			return ed25519.GeneratePrivateKey(rand)
		case mdoc.CurveEd448:
			return ed448.GeneratePrivateKey(rand)
		}
	} else {
		switch curve {
		case mdoc.CurveP256, mdoc.CurveP384, mdoc.CurveP521, mdoc.CurveX25519:
			return ecdh.GeneratePrivateKey(rand, curve)
		case mdoc.CurveX448:
			return x448.GeneratePrivateKey(rand)
		}
	}

	return nil, errors.New("TODO errors")
}
