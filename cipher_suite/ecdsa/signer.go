package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/alex-richards/go-mdoc"
)

var (
	ErrUnsupportedCurve     = errors.New("mdoc: ecdsa: unsupported curve")
	ErrInvalidASN1Signature = errors.New("mdoc: ecdsa: invalid ASN1 signature")
)

type Signer struct {
	signer          *ecdsa.PrivateKey
	curve           mdoc.Curve
	digestAlgorithm mdoc.DigestAlgorithm
}

func NewSigner(rand io.Reader, curve mdoc.Curve) (*Signer, error) {
	var ec elliptic.Curve
	var digestAlgorithm mdoc.DigestAlgorithm
	switch curve {
	case mdoc.CurveP256:
		ec = elliptic.P256()
		digestAlgorithm = mdoc.DigestAlgorithmSHA256

	case mdoc.CurveP384:
		ec = elliptic.P384()
		digestAlgorithm = mdoc.DigestAlgorithmSHA384

	case mdoc.CurveP521:
		ec = elliptic.P521()
		digestAlgorithm = mdoc.DigestAlgorithmSHA512

	default:
		return nil, ErrUnsupportedCurve
	}

	signer, err := ecdsa.GenerateKey(ec, rand)
	if err != nil {
		return nil, err
	}

	return &Signer{
		signer,
		curve,
		digestAlgorithm,
	}, nil
}

func (s Signer) Sign(rand io.Reader, data []byte) ([]byte, error) {
	sum, err := s.digestAlgorithm.Sum(data)
	if err != nil {
		return nil, err
	}

	signatureASN1, err := ecdsa.SignASN1(rand, s.signer, sum)
	if err != nil {
		return nil, err
	}

	return signatureASN1ToConcat(s.signer.Params(), signatureASN1)
}

func (s Signer) Curve() mdoc.Curve {
	return s.curve
}

func signatureASN1ToConcat(params *elliptic.CurveParams, signatureASN1 []byte) ([]byte, error) {
	type ECDSASignature struct {
		R *big.Int
		S *big.Int
	}

	signatureECDSA := new(ECDSASignature)
	rest, err := asn1.Unmarshal(signatureASN1, signatureECDSA)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidASN1Signature
	}

	rBytes := signatureECDSA.R.Bytes()
	sBytes := signatureECDSA.S.Bytes()

	size := (params.BitSize + 7) / 8

	if len(rBytes) > size || len(sBytes) > size {
		return nil, ErrInvalidASN1Signature
	}

	concatSignature := make([]byte, size*2)

	startR := size - len(rBytes)
	startS := (size * 2) - len(sBytes)

	copy(concatSignature[startR:], rBytes)
	copy(concatSignature[startS:], sBytes)

	return concatSignature, nil
}
