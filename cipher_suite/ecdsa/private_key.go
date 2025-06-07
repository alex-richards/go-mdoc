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
	ErrUnsupportedCurve = errors.New("mdoc: ecdsa: unsupported curve")
)

func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve) (*mdoc.PrivateKey, error) {
	signer, err := generateSigner(rand, curve)
	if err != nil {
		return nil, err
	}

	publicKey, err := toPublicKey(&signer.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    signer,
		Agreer:    nil,
		PublicKey: *publicKey,
	}, nil
}

func NewPrivateKey(curve mdoc.Curve, privateKey *ecdsa.PrivateKey) (*mdoc.PrivateKey, error) {
	signer, err := newSigner(curve, privateKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := toPublicKey(&signer.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    signer,
		Agreer:    nil,
		PublicKey: *publicKey,
	}, nil
}

func generateSigner(rand io.Reader, curve mdoc.Curve) (*signer, error) {
	var ellipticCurve elliptic.Curve
	switch curve {
	case mdoc.CurveP256:
		ellipticCurve = elliptic.P256()
	case mdoc.CurveP384:
		ellipticCurve = elliptic.P384()
	case mdoc.CurveP521:
		ellipticCurve = elliptic.P521()
	default:
		return nil, ErrUnsupportedCurve
	}

	privateKey, err := ecdsa.GenerateKey(ellipticCurve, rand)
	if err != nil {
		return nil, err
	}

	return newSigner(curve, privateKey)
}

func newSigner(curve mdoc.Curve, privateKey *ecdsa.PrivateKey) (*signer, error) {
	var digestAlgorithm mdoc.DigestAlgorithm
	switch curve {
	case mdoc.CurveP256:
		digestAlgorithm = mdoc.DigestAlgorithmSHA256
	case mdoc.CurveP384:
		digestAlgorithm = mdoc.DigestAlgorithmSHA384
	case mdoc.CurveP521:
		digestAlgorithm = mdoc.DigestAlgorithmSHA512
	default:
		return nil, ErrUnsupportedCurve
	}

	return &signer{
		*privateKey,
		curve,
		digestAlgorithm,
	}, nil
}

type signer struct {
	privateKey      ecdsa.PrivateKey
	curve           mdoc.Curve
	digestAlgorithm mdoc.DigestAlgorithm
}

func (s *signer) Curve() mdoc.Curve {
	return s.curve
}

func (s *signer) Sign(rand io.Reader, message []byte) ([]byte, error) {
	sum, err := s.digestAlgorithm.Sum(message)
	if err != nil {
		return nil, err
	}

	signatureASN1, err := ecdsa.SignASN1(rand, &s.privateKey, sum)
	if err != nil {
		return nil, err
	}

	return signatureASN1ToConcat(s.privateKey.Params(), signatureASN1), nil
}

func signatureASN1ToConcat(params *elliptic.CurveParams, signatureASN1 []byte) []byte {
	type ECDSASignature struct {
		R *big.Int
		S *big.Int
	}

	signatureECDSA := new(ECDSASignature)
	rest, err := asn1.Unmarshal(signatureASN1, signatureECDSA)
	if err != nil || len(rest) != 0 {
		panic("unexpected signature format")
	}

	size := (params.BitSize + 7) / 8
	bytes := make([]byte, size)

	concatSignature := make([]byte, size*2)

	signatureECDSA.R.FillBytes(bytes)
	copy(concatSignature, bytes)

	signatureECDSA.S.FillBytes(bytes)
	copy(concatSignature[size:], bytes)

	return concatSignature
}
