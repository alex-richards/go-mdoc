package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/alex-richards/go-mdoc"
)

func GeneratePrivateKey(rand io.Reader, curve mdoc.Curve) (*mdoc.PrivateKey, error) {
	var c elliptic.Curve
	switch curve {
	case mdoc.CurveP256:
		c = elliptic.P256()
	case mdoc.CurveP384:
		c = elliptic.P384()
	case mdoc.CurveP521:
		c = elliptic.P521()
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	privateKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, err
	}

	return newPrivateKey(curve, privateKey)
}

func NewPrivateKey(privateKey *ecdsa.PrivateKey) (*mdoc.PrivateKey, error) {
	var curve mdoc.Curve
	switch privateKey.Curve {
	case elliptic.P256():
		curve = mdoc.CurveP256
	case elliptic.P384():
		curve = mdoc.CurveP384
	case elliptic.P521():
		curve = mdoc.CurveP521
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	return newPrivateKey(curve, privateKey)
}

func newPrivateKey(curve mdoc.Curve, privateKey *ecdsa.PrivateKey) (*mdoc.PrivateKey, error) {
	var digestAlgorithm mdoc.DigestAlgorithm
	switch curve {
	case mdoc.CurveP256:
		digestAlgorithm = mdoc.DigestAlgorithmSHA256
	case mdoc.CurveP384:
		digestAlgorithm = mdoc.DigestAlgorithmSHA384
	case mdoc.CurveP521:
		digestAlgorithm = mdoc.DigestAlgorithmSHA512
	default:
		return nil, mdoc.ErrUnsupportedCurve
	}

	publicKey, err := toPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer: signer{
			privateKey:      *privateKey,
			curve:           curve,
			digestAlgorithm: digestAlgorithm,
		},
		PublicKey: *publicKey,
	}, nil
}

type signer struct {
	privateKey      ecdsa.PrivateKey
	curve           mdoc.Curve
	digestAlgorithm mdoc.DigestAlgorithm
}

func (s signer) Curve() mdoc.Curve {
	return s.curve
}

func (s signer) Sign(rand io.Reader, message []byte) ([]byte, error) {
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
