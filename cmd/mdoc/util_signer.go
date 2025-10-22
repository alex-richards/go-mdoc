package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
)

type cryptoSigner struct {
	signer crypto.Signer
}

func (s cryptoSigner) Curve() mdoc.Curve {
	switch privateKey := s.signer.(type) {
	case *ecdsa.PrivateKey:
		switch privateKey.Curve {
		case elliptic.P256():
			return mdoc.CurveP256
		case elliptic.P384():
			return mdoc.CurveP384
		case elliptic.P521():
			return mdoc.CurveP521
		}
	case ed25519.PrivateKey:
		return mdoc.CurveEd25519
	case ed448.PrivateKey:
		return mdoc.CurveEd448
	}

	return ""
}

func (s cryptoSigner) Sign(rand io.Reader, message []byte) ([]byte, error) {
	return s.signer.Sign(rand, message, nil)
}
