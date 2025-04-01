package mdoc

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

var (
	ErrUnsupportedCurve     = errors.New("mdoc: unsupported curve")
	ErrUnsupportedAlgorithm = errors.New("mdoc: unsupported algorithm")
	ErrInvalidASN1Signature = errors.New("mdoc: invalid ASN1 signature")
)

const (
	CipherSuiteVersion = 1
)

type Curve int

const (
	CurveP256 Curve = iota
	CurveP384
	CurveP521
	CurveX25519
	CurveX448
	CurveEd25519
	CurveEd448
	CurveBrainpoolP256r1
	CurveBrainpoolP320r1
	CurveBrainpoolP384r1
	CurveBrainpoolP512r1
)

type Signer interface {
	Curve() Curve
	Sign(rand io.Reader, data []byte) ([]byte, error)
}

type signerECDSA struct {
	key             *ecdsa.PrivateKey
	curve           Curve
	digestAlgorithm DigestAlgorithm
}

func (s *signerECDSA) Curve() Curve {
	return s.curve
}

func (s *signerECDSA) Sign(rand io.Reader, data []byte) ([]byte, error) {
	hash, err := s.digestAlgorithm.Hash()
	if err != nil {
		return nil, err
	}

	hash.Reset()
	hash.Write(data)
	digest := hash.Sum(nil)

	signatureASN1, err := ecdsa.SignASN1(rand, s.key, digest)
	if err != nil {
		return nil, err
	}

	return asn1SignatureToConcat(s.curve, signatureASN1)
}

func asn1SignatureToConcat(curve Curve, signatureASN1 []byte) ([]byte, error) {
	type EcdsaSignature struct {
		R *big.Int
		S *big.Int
	}

	signatureECDSA := new(EcdsaSignature)
	rest, err := asn1.Unmarshal(signatureASN1, signatureECDSA)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidASN1Signature
	}

	rBytes := signatureECDSA.R.Bytes()
	sBytes := signatureECDSA.S.Bytes()

	var size int
	switch curve {
	case CurveP256, CurveBrainpoolP256r1:
		size = 256
	case CurveP384, CurveBrainpoolP320r1:
		size = 384
	case CurveBrainpoolP384r1:
		size = 384
	case CurveP521, CurveBrainpoolP512r1:
		size = 521
	default:
		return nil, ErrUnsupportedCurve
	}
	byteSize := (size + 7) / 8

	if len(rBytes) > byteSize || len(sBytes) > byteSize {
		return nil, ErrUnsupportedSignatureFormat
	}

	concatSignature := make([]byte, byteSize*2)

	startR := byteSize - len(rBytes)
	startS := (byteSize * 2) - len(sBytes)

	copy(concatSignature[startR:], rBytes)
	copy(concatSignature[startS:], sBytes)

	return concatSignature, nil
}
